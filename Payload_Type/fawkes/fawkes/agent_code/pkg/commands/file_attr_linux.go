//go:build linux

package commands

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

// Linux ext2/3/4/xfs file attribute flags
const (
	fsSecureRemoval  = 0x00000001 // s: secure deletion
	fsUndelete       = 0x00000002 // u: undelete
	fsCompress       = 0x00000004 // c: compress
	fsSync           = 0x00000008 // S: synchronous updates
	fsImmutable      = 0x00000010 // i: immutable
	fsAppend         = 0x00000020 // a: append only
	fsNoDump         = 0x00000040 // d: no dump
	fsNoAtime        = 0x00000080 // A: no atime updates
	fsNoCoW          = 0x00800000 // C: no copy on write
)

// FS_IOC_GETFLAGS/SETFLAGS ioctl numbers (architecture-dependent via long size)
var (
	fsIocGetFlags = uintptr(2<<30 | int(unsafe.Sizeof(int(0)))<<16 | 0x66<<8 | 1)
	fsIocSetFlags = uintptr(1<<30 | int(unsafe.Sizeof(int(0)))<<16 | 0x66<<8 | 2)
)

type linuxAttrDef struct {
	name string
	flag int
}

var linuxAttrDefs = []linuxAttrDef{
	{"immutable", fsImmutable},
	{"append", fsAppend},
	{"nodump", fsNoDump},
	{"noatime", fsNoAtime},
	{"sync", fsSync},
	{"nocow", fsNoCoW},
}

func getFileAttrs(path string) structs.CommandResult {
	f, err := os.Open(path)
	if err != nil {
		return errorf("Error opening file: %v", err)
	}
	defer f.Close()

	var flags int
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetFlags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return errorf("Error getting attributes (filesystem may not support it): %v", errno)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] File attributes for: %s\n", path))
	sb.WriteString(fmt.Sprintf("    Raw flags: 0x%08X\n", flags))
	sb.WriteString("    Flags:\n")

	found := false
	for _, def := range linuxAttrDefs {
		if flags&def.flag != 0 {
			sb.WriteString(fmt.Sprintf("      [+] %s\n", def.name))
			found = true
		}
	}
	if !found {
		sb.WriteString("      (none)\n")
	}

	return successResult(sb.String())
}

func setFileAttrs(path string, attrsStr string) structs.CommandResult {
	add, remove, err := parseAttrChanges(attrsStr)
	if err != nil {
		return errorf("Error: %v", err)
	}

	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return errorf("Error opening file: %v", err)
	}
	defer f.Close()

	// Get current flags
	var flags int
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetFlags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return errorf("Error getting current attributes: %v", errno)
	}

	// Apply changes
	var changed []string
	for _, def := range linuxAttrDefs {
		if attrContains(add, def.name) {
			if flags&def.flag == 0 {
				flags |= def.flag
				changed = append(changed, "+"+def.name)
			}
		}
		if attrContains(remove, def.name) {
			if flags&def.flag != 0 {
				flags &^= def.flag
				changed = append(changed, "-"+def.name)
			}
		}
	}

	if len(changed) == 0 {
		return successf("[*] No attribute changes needed for %s", path)
	}

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocSetFlags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return errorf("Error setting attributes (may require root): %v", errno)
	}

	return successf("[+] Updated attributes on %s: %s", path, strings.Join(changed, ", "))
}
