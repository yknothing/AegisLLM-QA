//go:build windows

package harness

import "os"

func ignoreTermination() {}

func signalNotify(ch chan<- os.Signal) {}
