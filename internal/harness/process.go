// Package harness executes the system under test through bounded black-box
// process and HTTP lifecycle boundaries.
package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrOutputLimit    = errors.New("process output limit exceeded")
	ErrProcessExit    = errors.New("process exited unsuccessfully")
	ErrProcessTimeout = errors.New("process deadline exceeded")
	ErrHealthDeadline = errors.New("gateway health deadline exceeded")
)

const (
	processKillGrace = 100 * time.Millisecond
	healthPollPeriod = 25 * time.Millisecond
	healthBody       = `{"status":"ok"}`
)

// CommandResult contains bounded output. Callers must treat Truncated as a
// hard failure and must never interpolate Stdout or Stderr into evidence errors.
type CommandResult struct {
	ExitCode  int
	Stdout    string
	Stderr    string
	Truncated bool
	Duration  time.Duration
}

// Run executes an absolute binary with a minimal explicit environment. Both
// output streams are drained concurrently and bounded independently.
func Run(ctx context.Context, binary string, args []string, stdin []byte, env map[string]string, maxOutput int) (CommandResult, error) {
	started := time.Now()
	result := CommandResult{ExitCode: -1}
	if ctx == nil {
		return result, errors.New("process context is required")
	}
	if !filepath.IsAbs(binary) {
		return result, errors.New("process binary must be absolute")
	}
	if maxOutput <= 0 {
		return result, errors.New("process output limit must be positive")
	}
	childEnv, err := minimalEnvironment(env)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, ErrProcessTimeout
	}

	command := exec.Command(binary, args...)
	configureProcessGroup(command)
	command.Env = childEnv
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}

	overflow := make(chan struct{}, 1)
	notifyOverflow := func() {
		select {
		case overflow <- struct{}{}:
		default:
		}
	}
	stdout := newBoundedBuffer(maxOutput, notifyOverflow)
	stderr := newBoundedBuffer(maxOutput, notifyOverflow)
	command.Stdout = stdout
	command.Stderr = stderr

	if err := command.Start(); err != nil {
		result.Duration = time.Since(started)
		return result, errors.New("start process")
	}
	done := make(chan struct{})
	go enforceTermination(ctx, command, overflow, done, processKillGrace)
	waitErr := command.Wait() // The sole Wait call for this process.
	close(done)

	result.Stdout, _ = stdout.snapshot()
	result.Stderr, _ = stderr.snapshot()
	_, stdoutOverflow := stdout.snapshot()
	_, stderrOverflow := stderr.snapshot()
	result.Truncated = stdoutOverflow || stderrOverflow
	result.Duration = time.Since(started)
	if command.ProcessState != nil {
		result.ExitCode = command.ProcessState.ExitCode()
	}
	if result.Truncated {
		return result, ErrOutputLimit
	}
	if ctx.Err() != nil {
		return result, ErrProcessTimeout
	}
	if waitErr != nil || result.ExitCode != 0 {
		return result, ErrProcessExit
	}
	return result, nil
}

// Gateway owns one long-running SUT process and its bounded log buffers.
type Gateway struct {
	command *exec.Cmd
	stdout  *boundedBuffer
	stderr  *boundedBuffer

	healthTransport http.RoundTripper

	done chan struct{}

	stateMu sync.Mutex
	waitErr error

	signalOnce sync.Once
	killOnce   sync.Once
}

// StartGateway starts the SUT with its documented config flag. The supplied
// environment is filtered by the same minimal policy as Run.
func StartGateway(ctx context.Context, binary, configPath string, env map[string]string, logLimit int) (*Gateway, error) {
	if ctx == nil {
		return nil, errors.New("gateway context is required")
	}
	if !filepath.IsAbs(binary) {
		return nil, errors.New("gateway binary must be absolute")
	}
	if logLimit <= 0 {
		return nil, errors.New("gateway log limit must be positive")
	}
	childEnv, err := minimalEnvironment(env)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrProcessTimeout
	}

	command := exec.Command(binary, "-config", configPath)
	configureProcessGroup(command)
	command.Env = childEnv
	gateway := &Gateway{command: command, done: make(chan struct{})}
	overflow := func() {
		gateway.requestTerminate()
		go gateway.killAfter(processKillGrace)
	}
	gateway.stdout = newBoundedBuffer(logLimit, overflow)
	gateway.stderr = newBoundedBuffer(logLimit, overflow)
	command.Stdout = gateway.stdout
	command.Stderr = gateway.stderr

	if err := command.Start(); err != nil {
		return nil, errors.New("start gateway")
	}
	go func() {
		err := command.Wait() // The sole Wait call for the gateway process.
		gateway.stateMu.Lock()
		gateway.waitErr = err
		gateway.stateMu.Unlock()
		close(gateway.done)
	}()
	go func() {
		select {
		case <-ctx.Done():
			gateway.requestTerminate()
			gateway.killAfter(processKillGrace)
		case <-gateway.done:
		}
	}()
	return gateway, nil
}

// WaitHealthy polls the public health endpoint until success, process failure,
// output overflow, or the caller's deadline. Response bodies are discarded
// through a small bound and never included in errors.
func (g *Gateway) WaitHealthy(ctx context.Context, url string) error {
	if ctx == nil {
		return errors.New("health context is required")
	}
	var transport http.RoundTripper
	closeIdleConnections := func() {}
	if g.healthTransport != nil {
		transport = g.healthTransport
	} else {
		defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
		defaultTransport.Proxy = nil
		transport = defaultTransport
		closeIdleConnections = defaultTransport.CloseIdleConnections
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   250 * time.Millisecond,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer closeIdleConnections()

	ticker := time.NewTicker(healthPollPeriod)
	defer ticker.Stop()
	for {
		if g.outputOverflowed() {
			return ErrOutputLimit
		}
		select {
		case <-g.done:
			if g.outputOverflowed() {
				return ErrOutputLimit
			}
			return ErrProcessExit
		default:
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return errors.New("construct health request")
		}
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(len(healthBody)+1)))
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && string(body) == healthBody {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ErrHealthDeadline
		case <-g.done:
			if g.outputOverflowed() {
				return ErrOutputLimit
			}
			return ErrProcessExit
		case <-ticker.C:
		}
	}
}

// Stop requests process-group SIGTERM, waits until the supplied deadline, then
// uses process-group SIGKILL and waits for the single Wait owner to complete.
func (g *Gateway) Stop(ctx context.Context) error {
	if ctx == nil {
		return errors.New("stop context is required")
	}
	select {
	case <-g.done:
		if g.outputOverflowed() {
			return ErrOutputLimit
		}
		return g.unexpectedExitError()
	default:
	}

	g.requestTerminate()
	select {
	case <-g.done:
		if g.outputOverflowed() {
			return ErrOutputLimit
		}
		return g.requestedStopExitError()
	case <-ctx.Done():
		g.forceKill()
		<-g.done
		if g.outputOverflowed() {
			return ErrOutputLimit
		}
		return ErrProcessTimeout
	}
}

// Logs returns defensive snapshots of both bounded streams.
func (g *Gateway) Logs() (stdout, stderr string, truncated bool) {
	stdout, stdoutOverflow := g.stdout.snapshot()
	stderr, stderrOverflow := g.stderr.snapshot()
	return stdout, stderr, stdoutOverflow || stderrOverflow
}

func (g *Gateway) requestTerminate() {
	g.signalOnce.Do(func() { _ = terminateProcessGroup(g.command) })
}

func (g *Gateway) forceKill() {
	g.killOnce.Do(func() { _ = killProcessGroup(g.command) })
}

func (g *Gateway) killAfter(grace time.Duration) {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-g.done:
		return
	case <-timer.C:
		g.forceKill()
	}
}

func (g *Gateway) outputOverflowed() bool {
	_, stdoutOverflow := g.stdout.snapshot()
	_, stderrOverflow := g.stderr.snapshot()
	return stdoutOverflow || stderrOverflow
}

func (g *Gateway) unexpectedExitError() error {
	g.stateMu.Lock()
	waitErr := g.waitErr
	g.stateMu.Unlock()
	if waitErr != nil || g.command.ProcessState == nil || g.command.ProcessState.ExitCode() != 0 {
		return ErrProcessExit
	}
	return nil
}

func (g *Gateway) requestedStopExitError() error {
	g.stateMu.Lock()
	waitErr := g.waitErr
	state := g.command.ProcessState
	g.stateMu.Unlock()
	if waitErr == nil && state != nil && state.ExitCode() == 0 {
		return nil
	}
	if expectedTermination(state) {
		return nil
	}
	return ErrProcessExit
}

type boundedBuffer struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	overflow bool
	once     sync.Once
	notify   func()
}

func newBoundedBuffer(limit int, notify func()) *boundedBuffer {
	return &boundedBuffer{limit: limit, notify: notify}
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	if b.overflow {
		b.mu.Unlock()
		return 0, ErrOutputLimit
	}
	remaining := b.limit - b.buffer.Len()
	if len(data) <= remaining {
		n, err := b.buffer.Write(data)
		b.mu.Unlock()
		return n, err
	}
	if remaining > 0 {
		_, _ = b.buffer.Write(data[:remaining])
	}
	b.overflow = true
	b.mu.Unlock()
	b.once.Do(func() {
		if b.notify != nil {
			b.notify()
		}
	})
	return remaining, ErrOutputLimit
}

func (b *boundedBuffer) snapshot() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String(), b.overflow
}

func enforceTermination(ctx context.Context, command *exec.Cmd, overflow <-chan struct{}, done <-chan struct{}, grace time.Duration) {
	select {
	case <-ctx.Done():
	case <-overflow:
	case <-done:
		return
	}
	_ = terminateProcessGroup(command)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		_ = killProcessGroup(command)
	}
}

func minimalEnvironment(input map[string]string) ([]string, error) {
	values := map[string]string{
		"PATH":   defaultPath(),
		"HOME":   os.TempDir(),
		"TMPDIR": os.TempDir(),
	}
	for key, value := range input {
		if !validEnvironmentKey(key) {
			return nil, errors.New("invalid child environment key")
		}
		if !allowedEnvironmentKey(key) {
			return nil, fmt.Errorf("child environment key %s is not allowed", key)
		}
		if strings.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("child environment value for %s is invalid", key)
		}
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment, nil
}

func validEnvironmentKey(key string) bool {
	if key == "" || strings.ContainsAny(key, "=\x00") {
		return false
	}
	return true
}

func allowedEnvironmentKey(key string) bool {
	return key == "PATH" || key == "HOME" || key == "TMPDIR" ||
		key == "SSL_CERT_FILE" || key == "SSL_CERT_DIR" || strings.HasPrefix(key, "AEGIS_")
}

func defaultPath() string {
	if runtime.GOOS == "windows" {
		return `C:\\Windows\\System32;C:\\Windows`
	}
	return "/usr/local/bin:/usr/bin:/bin"
}
