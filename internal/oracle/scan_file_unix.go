//go:build !windows

package oracle

import (
	"os"
	"syscall"
)

func openScanFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrScanTree
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = syscall.Close(fd)
		return nil, ErrScanTree
	}
	file := os.NewFile(uintptr(fd), "")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrScanTree
	}
	return file, nil
}
