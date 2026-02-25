//go:build darwin

package commands

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	sysProcInfo           = 336 // SYS_PROC_INFO
	procInfoCallPidInfo   = 2   // PROC_INFO_CALL_PIDINFO
	procPidRegionInfo     = 7   // PROC_PIDREGIONINFO
	procPidRegionPathInfo = 13  // PROC_PIDREGIONPATHINFO2
)

// procRegionInfoDarwin matches XNU's proc_regioninfo struct (96 bytes)
type procRegionInfoDarwin struct {
	Protection            uint32
	MaxProtection         uint32
	Inheritance           uint32
	Flags                 uint32
	Offset                uint64
	Behavior              uint32
	UserWiredCount        uint32
	UserTag               uint32
	PagesResident         uint32
	PagesSharedNowPrivate uint32
	PagesSwappedOut       uint32
	PagesDirtied          uint32
	RefCount              uint32
	ShadowDepth           uint32
	ShareMode             uint32
	PrivatePagesResident  uint32
	SharedPagesResident   uint32
	ObjID                 uint32
	Depth                 uint32
	Address               uint64
	Size                  uint64
}

func procPidInfoCall(pid int, flavor int, arg uint64, buf unsafe.Pointer, bufSize int) (int, error) {
	r1, _, e1 := syscall.Syscall6(
		sysProcInfo,
		procInfoCallPidInfo,
		uintptr(pid),
		uintptr(flavor),
		uintptr(arg),
		uintptr(buf),
		uintptr(bufSize),
	)
	if e1 != 0 {
		return int(r1), e1
	}
	return int(r1), nil
}

func listProcessModules(pid int) ([]ModuleInfo, error) {
	var modules []ModuleInfo
	seen := make(map[string]bool)

	var addr uint64 = 1 // Start at 1 — flavor 7 returns EINVAL for 0
	maxIter := 100000   // Safety limit

	for i := 0; i < maxIter; i++ {
		// Get region info (address + size)
		var ri procRegionInfoDarwin
		n, err := procPidInfoCall(pid, procPidRegionInfo, addr, unsafe.Pointer(&ri), int(unsafe.Sizeof(ri)))
		if err != nil || n == 0 {
			break
		}

		if ri.Size == 0 {
			break
		}

		// Get the path for this region
		pathBuf := make([]byte, 1024)
		pn, _ := procPidInfoCall(pid, procPidRegionPathInfo, ri.Address, unsafe.Pointer(&pathBuf[0]), len(pathBuf))
		if pn > 0 {
			// Find null terminator
			pathLen := 0
			for pathLen < pn && pathBuf[pathLen] != 0 {
				pathLen++
			}
			path := string(pathBuf[:pathLen])

			if path != "" && strings.HasPrefix(path, "/") && !seen[path] {
				seen[path] = true
				modules = append(modules, ModuleInfo{
					Name:     filepath.Base(path),
					Path:     path,
					BaseAddr: fmt.Sprintf("0x%X", ri.Address),
					Size:     ri.Size,
				})
			}
		}

		// Advance to next region
		nextAddr := ri.Address + ri.Size
		if nextAddr <= addr {
			break // Overflow or no progress
		}
		addr = nextAddr
	}

	if len(modules) == 0 {
		return nil, fmt.Errorf("no modules found (may require same-user ownership or root for PID %d)", pid)
	}

	return modules, nil
}
