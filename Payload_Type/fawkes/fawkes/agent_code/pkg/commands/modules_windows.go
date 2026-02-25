//go:build windows

package commands

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	thSnapModule   = 0x00000008
	thSnapModule32 = 0x00000010
	maxModuleName  = 256
)

// moduleEntry32W matches the Windows MODULEENTRY32W structure
type moduleEntry32W struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	HModule      uintptr
	Module       [maxModuleName + 1]uint16
	ExePath      [windows.MAX_PATH]uint16
}

var (
	modKernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procModule32FirstW = modKernel32.NewProc("Module32FirstW")
	procModule32NextW  = modKernel32.NewProc("Module32NextW")
)

func listProcessModules(pid int) ([]ModuleInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(thSnapModule|thSnapModule32, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %v", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()

	var me moduleEntry32W
	me.Size = uint32(unsafe.Sizeof(me))

	ret, _, err := procModule32FirstW.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
	if ret == 0 {
		return nil, fmt.Errorf("Module32FirstW: %v", err)
	}

	var modules []ModuleInfo
	for {
		name := windows.UTF16ToString(me.Module[:])
		path := windows.UTF16ToString(me.ExePath[:])

		modules = append(modules, ModuleInfo{
			Name:     name,
			Path:     path,
			BaseAddr: fmt.Sprintf("0x%X", me.ModBaseAddr),
			Size:     uint64(me.ModBaseSize),
		})

		me.Size = uint32(unsafe.Sizeof(me))
		ret, _, _ = procModule32NextW.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
		if ret == 0 {
			break
		}
	}

	return modules, nil
}
