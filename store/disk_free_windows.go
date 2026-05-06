//go:build windows

package store

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// diskFreeAt returns the free bytes available to the current user at
// the given path's filesystem. Uses GetDiskFreeSpaceEx, which returns
// the per-user free-bytes-available value (honors per-user quotas
// where they exist; on most operator boxes this matches the raw
// volume free).
//
// Windows build tag. Unix variant lives in disk_free_unix.go.
func diskFreeAt(path string) (int64, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("utf16 path: %w", err)
	}
	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes); err != nil {
		return 0, fmt.Errorf("GetDiskFreeSpaceEx %s: %w", path, err)
	}
	// freeBytesAvailable is the per-user free space — matches what a
	// write attempt would actually be allowed to consume. Cast through
	// int64 with a high-bit safety check (volumes >8 EB are not a
	// concern but let's be explicit).
	if freeBytesAvailable > (1 << 62) {
		return 1 << 62, nil
	}
	return int64(freeBytesAvailable), nil
}
