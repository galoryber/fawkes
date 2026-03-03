//go:build darwin

package commands

import (
	"golang.org/x/sys/unix"
)

// getfsstatMounts uses the getfsstat(2) syscall to enumerate mounted filesystems
// on macOS without spawning a child process. This replaces the `mount` command
// fallback with a direct kernel query.
func getfsstatMounts() []mountEntry {
	// First call with nil buf to get the count of mounted filesystems
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil || n == 0 {
		return nil
	}

	buf := make([]unix.Statfs_t, n)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil || n == 0 {
		return nil
	}

	var mounts []mountEntry
	for _, fs := range buf[:n] {
		fsType := byteSliceToString(fs.Fstypename[:])
		device := byteSliceToString(fs.Mntfromname[:])
		mountPoint := byteSliceToString(fs.Mntonname[:])

		if shouldSkipFs(fsType, device) {
			continue
		}

		mounts = append(mounts, mountEntry{
			device:     device,
			mountPoint: mountPoint,
			fsType:     fsType,
		})
	}
	return mounts
}

// byteSliceToString converts a null-terminated byte slice to a Go string.
func byteSliceToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
