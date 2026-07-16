package oracle

import "io"

// readScanFile returns one bounded regular-file buffer. The caller owns the
// returned buffer and must clear it; every failure path clears partial data.
func readScanFile(path string) (data []byte, err error) {
	file, err := openScanFile(path)
	if err != nil {
		return nil, ErrScanTree
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			clear(data)
			data = nil
			err = ErrScanTree
		}
	}()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxScanFileBytes {
		return nil, ErrScanTree
	}
	data, err = io.ReadAll(io.LimitReader(file, maxScanFileBytes+1))
	if err != nil {
		clear(data)
		return nil, ErrScanTree
	}
	if len(data) > maxScanFileBytes {
		clear(data)
		return nil, ErrScanTree
	}
	return data, nil
}
