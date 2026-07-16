//go:build !windows

package harness

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func ignoreTermination() {
	signal.Ignore(syscall.SIGTERM, syscall.SIGINT)
}

func signalNotify(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
}

func TestRunContextTimeoutKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	result, err := Run(ctx, os.Args[0], []string{"-test.run=TestProcessHelper", "--", "spawn-child"}, nil, map[string]string{
		"AEGIS_QA_HELPER":      "1",
		"AEGIS_CHILD_PID_FILE": pidFile,
	}, 1<<20)
	if err == nil || !errors.Is(err, ErrProcessTimeout) {
		t.Fatalf("Run() error = %v, result = %#v, want ErrProcessTimeout", err, result)
	}

	pidBytes, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("read child pid: %v", readErr)
	}
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	deadline := time.Now().Add(2 * time.Second)
	for processExists(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processExists(pid) {
		t.Fatalf("descendant process %d survived process-group kill", pid)
	}
}

func TestGatewayStopAcceptsRequestedSIGTERM(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	gateway, err := StartGateway(context.Background(), os.Args[0], "ignored.json", map[string]string{
		"AEGIS_QA_HELPER":    "1",
		"AEGIS_HELPER_MODE":  "signal-terminated",
		"AEGIS_READY_MARKER": ready,
	}, 1<<20)
	if err != nil {
		t.Fatalf("StartGateway() error = %v", err)
	}
	waitForMarker(t, ready)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := gateway.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v, want requested SIGTERM accepted", err)
	}
}

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
