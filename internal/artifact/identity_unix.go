//go:build !windows

package artifact

import (
	"os"
	"syscall"
)

func openArtifactNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
