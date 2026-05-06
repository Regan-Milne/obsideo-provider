//go:build !windows

package store

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// diskFreeAt returns the free bytes available to a non-root caller at
// the given path's filesystem. Uses statfs(2) and reports
// `Bavail * Bsize`, which excludes the reserved-for-root slice and is
// the right number for "how much can we actually write."
//
// Unix build tag: linux, darwin, BSDs. Windows variant lives in
// disk_free_windows.go via the //go:build windows tag.
func diskFreeAt(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	// Bavail is the number of blocks available to non-root users.
	// Bsize is the optimal transfer block size (effectively the
	// filesystem block size on every modern unix). Multiply with
	// int64 conversion to avoid overflow on multi-TB volumes.
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}
