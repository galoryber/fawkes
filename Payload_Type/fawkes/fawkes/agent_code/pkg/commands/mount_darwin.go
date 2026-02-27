package commands

import (
	"syscall"
	"unsafe"
)

func getMountInfo() ([]mountInfoEntry, error) {
	n, err := syscall.Getfsstat(nil, 1) // MNT_NOWAIT
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}

	buf := make([]syscall.Statfs_t, n)
	n, err = syscall.Getfsstat(buf, 1)
	if err != nil {
		return nil, err
	}
	buf = buf[:n]

	var entries []mountInfoEntry
	for _, s := range buf {
		fstype := cstrMount((*[256]byte)(unsafe.Pointer(&s.Fstypename))[:])
		device := cstrMount((*[1024]byte)(unsafe.Pointer(&s.Mntfromname))[:])
		mountpoint := cstrMount((*[1024]byte)(unsafe.Pointer(&s.Mntonname))[:])

		opts := mountFlagsStr(s.Flags)

		entries = append(entries, mountInfoEntry{
			device:   device,
			mntPoint: mountpoint,
			mntType:  fstype,
			mntOpts:  opts,
		})
	}

	return entries, nil
}

func cstrMount(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func mountFlagsStr(flags uint32) string {
	var parts []string
	if flags&0x1 != 0 {
		parts = append(parts, "rdonly")
	} else {
		parts = append(parts, "rw")
	}
	if flags&0x4 != 0 {
		parts = append(parts, "nosuid")
	}
	if flags&0x8 != 0 {
		parts = append(parts, "nodev")
	}
	if flags&0x40 != 0 {
		parts = append(parts, "noatime")
	}
	if len(parts) == 0 {
		return "rw"
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += "," + parts[i]
	}
	return result
}
