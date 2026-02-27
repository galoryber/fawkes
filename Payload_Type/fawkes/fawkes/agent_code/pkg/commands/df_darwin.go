package commands

import (
	"syscall"
	"unsafe"
)

func getDiskFreeInfo() ([]dfEntry, error) {
	// Use getmntinfo via syscall.Statfs
	var buf []syscall.Statfs_t
	n, err := syscall.Getfsstat(nil, 1) // MNT_NOWAIT = 1
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}

	buf = make([]syscall.Statfs_t, n)
	n, err = syscall.Getfsstat(buf, 1)
	if err != nil {
		return nil, err
	}
	buf = buf[:n]

	var entries []dfEntry
	for _, s := range buf {
		fstype := cstr((*[256]byte)(unsafe.Pointer(&s.Fstypename))[:])
		// Skip virtual filesystems
		if fstype == "devfs" || fstype == "autofs" {
			continue
		}

		device := cstr((*[1024]byte)(unsafe.Pointer(&s.Mntfromname))[:])
		mountpoint := cstr((*[1024]byte)(unsafe.Pointer(&s.Mntonname))[:])

		total := uint64(s.Blocks) * uint64(s.Bsize)
		avail := uint64(s.Bavail) * uint64(s.Bsize)
		free := uint64(s.Bfree) * uint64(s.Bsize)
		used := total - free

		entries = append(entries, dfEntry{
			device:     device,
			fstype:     fstype,
			mountpoint: mountpoint,
			total:      total,
			used:       used,
			avail:      avail,
		})
	}

	return entries, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
