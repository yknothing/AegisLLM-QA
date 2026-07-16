//go:build windows

package harness

import (
	"os"
	"os/exec"
)

func configureProcessGroup(command *exec.Cmd) {}

func terminateProcessGroup(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return nil
	}
	return command.Process.Signal(os.Interrupt)
}

func killProcessGroup(command *exec.Cmd) error {
	if command == nil || command.Process == nil {
		return nil
	}
	return command.Process.Kill()
}

func expectedTermination(_ *os.ProcessState) bool {
	return false
}
