package harness

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var helperConfigFlag = flag.String("config", "", "helper-process compatibility flag")

func TestMain(m *testing.M) {
	if os.Getenv("AEGIS_QA_HELPER") == "1" {
		switch os.Getenv("AEGIS_HELPER_MODE") {
		case "gateway":
			runGatewayHelper()
		case "sleep":
			ignoreTermination()
			waitForever()
		case "stop-nonzero":
			runStopExitHelper(7)
		case "signal-terminated":
			if err := os.WriteFile(os.Getenv("AEGIS_READY_MARKER"), []byte("ready"), 0o600); err != nil {
				os.Exit(4)
			}
			waitForever()
		}
	}
	os.Exit(m.Run())
}

func TestRunStdinMinimalEnvironmentAndSeparateOutput(t *testing.T) {
	t.Setenv("REAL_SECRET", "must-not-cross-boundary")
	t.Setenv("HTTP_PROXY", "http://real-proxy.invalid")
	t.Setenv("AEGIS_REAL_CONFIG", "/real/config")

	result, err := Run(
		context.Background(),
		os.Args[0],
		[]string{"-test.run=TestProcessHelper", "--", "echo"},
		[]byte("synthetic-provider-key"),
		map[string]string{
			"AEGIS_QA_HELPER":  "1",
			"AEGIS_TEST_VALUE": "synthetic-value",
		},
		1024,
	)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Stdout != "stdin=synthetic-provider-key env=synthetic-value inherited=\n" {
		t.Fatalf("stdout = %q", result.Stdout)
	}
	if result.Stderr != "separate-stderr\n" {
		t.Fatalf("stderr = %q", result.Stderr)
	}
	if result.ExitCode != 0 || result.Truncated {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunNonZeroExitDoesNotEchoCapturedOutputInError(t *testing.T) {
	const canary = "raw-output-canary-do-not-disclose"
	result, err := Run(context.Background(), os.Args[0], []string{"-test.run=TestProcessHelper", "--", "exit", canary}, nil, helperEnv(), 1024)
	if err == nil || !errors.Is(err, ErrProcessExit) {
		t.Fatalf("Run() error = %v, want ErrProcessExit", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatal("Run() error leaked raw process output")
	}
	if result.ExitCode != 7 || !strings.Contains(result.Stderr, canary) {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunOutputOverflowFailsImmediately(t *testing.T) {
	started := time.Now()
	result, err := Run(context.Background(), os.Args[0], []string{"-test.run=TestProcessHelper", "--", "overflow"}, nil, helperEnv(), 32)
	if err == nil || !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("Run() error = %v, want ErrOutputLimit", err)
	}
	if !result.Truncated {
		t.Fatal("overflow result did not record truncation")
	}
	if len(result.Stdout) > 32 || len(result.Stderr) > 32 {
		t.Fatalf("captured output exceeded bound: stdout=%d stderr=%d", len(result.Stdout), len(result.Stderr))
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("overflow termination took %v, want immediate failure", elapsed)
	}
}

func TestGatewayWaitHealthyAndGracefulStop(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "stopped")

	gateway, err := StartGateway(context.Background(), os.Args[0], "ignored.json", map[string]string{
		"AEGIS_QA_HELPER":   "1",
		"AEGIS_HELPER_MODE": "gateway",
		"AEGIS_TEST_ADDR":   addr,
		"AEGIS_STOP_MARKER": marker,
	}, 1<<20)
	if err != nil {
		t.Fatalf("StartGateway() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = gateway.Stop(ctx)
	})

	healthCtx, cancelHealth := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelHealth()
	if err := gateway.WaitHealthy(healthCtx, "http://"+addr+"/health"); err != nil {
		t.Fatalf("WaitHealthy() error = %v", err)
	}

	stopCtx, cancelStop := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelStop()
	if err := gateway.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("graceful stop marker: %v", err)
	}
	stdout, stderr, truncated := gateway.Logs()
	if truncated || !strings.Contains(stdout, "gateway-ready") || stderr != "" {
		t.Fatalf("Logs() = %q, %q, %v", stdout, stderr, truncated)
	}
}

func TestGatewayStopRejectsNonZeroExitAfterTerminationRequest(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	gateway, err := StartGateway(context.Background(), os.Args[0], "ignored.json", map[string]string{
		"AEGIS_QA_HELPER":    "1",
		"AEGIS_HELPER_MODE":  "stop-nonzero",
		"AEGIS_READY_MARKER": ready,
	}, 1<<20)
	if err != nil {
		t.Fatalf("StartGateway() error = %v", err)
	}
	waitForMarker(t, ready)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := gateway.Stop(ctx); !errors.Is(err, ErrProcessExit) {
		t.Fatalf("Stop() error = %v, want ErrProcessExit", err)
	}
}

func TestGatewayHealthDeadlineIsBoundedAndSanitized(t *testing.T) {
	gateway, err := StartGateway(context.Background(), os.Args[0], "ignored.json", map[string]string{
		"AEGIS_QA_HELPER":   "1",
		"AEGIS_HELPER_MODE": "sleep",
	}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_ = gateway.Stop(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err = gateway.WaitHealthy(ctx, "http://127.0.0.1:1/health?secret=raw-canary")
	if err == nil || !errors.Is(err, ErrHealthDeadline) {
		t.Fatalf("WaitHealthy() error = %v, want ErrHealthDeadline", err)
	}
	if strings.Contains(err.Error(), "raw-canary") {
		t.Fatal("health error disclosed URL contents")
	}
}

func TestGatewayWaitHealthyDoesNotFollowRedirects(t *testing.T) {
	var redirectedRequests atomic.Int32
	gateway := &Gateway{
		stdout: newBoundedBuffer(1024, nil),
		stderr: newBoundedBuffer(1024, nil),
		done:   make(chan struct{}),
		healthTransport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Host == "redirected.invalid" {
				redirectedRequests.Add(1)
				return healthResponse(request, http.StatusOK, healthBody), nil
			}
			response := healthResponse(request, http.StatusFound, "")
			response.Header.Set("Location", "http://redirected.invalid/health")
			return response, nil
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := gateway.WaitHealthy(ctx, "http://gateway.invalid/health"); !errors.Is(err, ErrHealthDeadline) {
		t.Fatalf("WaitHealthy() error = %v, want ErrHealthDeadline", err)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("WaitHealthy() followed redirect %d times", got)
	}
}

func TestGatewayWaitHealthyRequiresExactHealthyBody(t *testing.T) {
	gateway := &Gateway{
		stdout: newBoundedBuffer(1024, nil),
		stderr: newBoundedBuffer(1024, nil),
		done:   make(chan struct{}),
		healthTransport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return healthResponse(request, http.StatusOK, healthBody+"\n"), nil
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := gateway.WaitHealthy(ctx, "http://gateway.invalid/health"); !errors.Is(err, ErrHealthDeadline) {
		t.Fatalf("WaitHealthy() error = %v, want ErrHealthDeadline", err)
	}
}

func TestGatewayWaitHealthyAcceptsDirectExactHealthyResponse(t *testing.T) {
	gateway := &Gateway{
		stdout: newBoundedBuffer(1024, nil),
		stderr: newBoundedBuffer(1024, nil),
		done:   make(chan struct{}),
		healthTransport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return healthResponse(request, http.StatusOK, healthBody), nil
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := gateway.WaitHealthy(ctx, "http://gateway.invalid/health"); err != nil {
		t.Fatalf("WaitHealthy() error = %v", err)
	}
}

func TestProcessHelper(t *testing.T) {
	if os.Getenv("AEGIS_QA_HELPER") != "1" {
		return
	}
	args := argsAfterDoubleDash(os.Args)
	if len(args) == 0 {
		switch os.Getenv("AEGIS_HELPER_MODE") {
		case "gateway":
			runGatewayHelper()
		case "sleep":
			ignoreTermination()
			waitForever()
		}
		os.Exit(3)
	}

	switch args[0] {
	case "echo":
		stdin, _ := io.ReadAll(os.Stdin)
		inherited := os.Getenv("REAL_SECRET") + os.Getenv("HTTP_PROXY") + os.Getenv("AEGIS_REAL_CONFIG")
		fmt.Printf("stdin=%s env=%s inherited=%s\n", stdin, os.Getenv("AEGIS_TEST_VALUE"), inherited)
		fmt.Fprintln(os.Stderr, "separate-stderr")
		os.Exit(0)
	case "exit":
		fmt.Fprintln(os.Stderr, args[1])
		os.Exit(7)
	case "overflow":
		fmt.Fprint(os.Stdout, strings.Repeat("x", 4096))
		ignoreTermination()
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "spawn-child":
		child := exec.Command(os.Args[0], "-test.run=TestProcessHelper", "--", "child")
		child.Env = os.Environ()
		if err := child.Start(); err != nil {
			os.Exit(4)
		}
		_ = os.WriteFile(os.Getenv("AEGIS_CHILD_PID_FILE"), []byte(strconv.Itoa(child.Process.Pid)), 0o600)
		ignoreTermination()
		waitForever()
	case "child":
		ignoreTermination()
		waitForever()
	default:
		os.Exit(5)
	}
}

func runGatewayHelper() {
	server := &http.Server{Addr: os.Getenv("AEGIS_TEST_ADDR"), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "{\"status\":\"ok\"}")
			return
		}
		http.NotFound(w, r)
	})}
	termination := make(chan os.Signal, 1)
	signalNotify(termination)
	go func() {
		<-termination
		_ = os.WriteFile(os.Getenv("AEGIS_STOP_MARKER"), []byte("stopped"), 0o600)
		_ = server.Close()
	}()
	fmt.Fprintln(os.Stdout, "gateway-ready")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		os.Exit(6)
	}
	os.Exit(0)
}

func runStopExitHelper(code int) {
	termination := make(chan os.Signal, 1)
	signalNotify(termination)
	if err := os.WriteFile(os.Getenv("AEGIS_READY_MARKER"), []byte("ready"), 0o600); err != nil {
		os.Exit(4)
	}
	<-termination
	os.Exit(code)
}

func helperEnv() map[string]string { return map[string]string{"AEGIS_QA_HELPER": "1"} }

func waitForever() {
	for {
		time.Sleep(time.Hour)
	}
}

func argsAfterDoubleDash(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			return args[i+1:]
		}
	}
	return nil
}

func waitForMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("helper did not create ready marker %q", path)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func healthResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}
