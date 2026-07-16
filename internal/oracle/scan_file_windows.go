//go:build windows

package oracle

import (
	"os"
	"syscall"
)

func openScanFile(path string) (*os.File, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrScanTree
	}
	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, ErrScanTree
	}
	file := os.NewFile(uintptr(handle), "")
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, ErrScanTree
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrScanTree
	}
	return file, nil
}
