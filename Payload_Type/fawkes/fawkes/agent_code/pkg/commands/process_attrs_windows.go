//go:build windows
// +build windows

package commands

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// initProcAttrList initializes a PROC_THREAD_ATTRIBUTE_LIST with optional PPID
// spoofing and DLL blocking attributes. Returns the attribute list, parent
// handle (0 if no PPID spoofing), a cleanup function, and any error.
// The caller must defer cleanup() and close parentHandle if non-zero.
func initProcAttrList(ppid int, blockDLLs bool) (*PROC_THREAD_ATTRIBUTE_LIST, windows.Handle, func(), error) {
	attrCount := 0
	if ppid > 0 {
		attrCount++
	}
	if blockDLLs {
		attrCount++
	}
	if attrCount == 0 {
		attrCount = 1
	}

	var attrListSize uintptr
	procInitializeProcThreadAttributeList.Call(0, uintptr(attrCount), 0, uintptr(unsafe.Pointer(&attrListSize)))

	attrListBuf := make([]byte, attrListSize)
	attrList := (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(&attrListBuf[0]))

	ret, _, err := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(attrList)), uintptr(attrCount), 0,
		uintptr(unsafe.Pointer(&attrListSize)),
	)
	if ret == 0 {
		return nil, 0, func() {}, fmt.Errorf("InitializeProcThreadAttributeList: %w", err)
	}
	cleanup := func() {
		procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(attrList)))
	}

	var parentHandle windows.Handle
	if ppid > 0 {
		hParent, errOpen := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, uint32(ppid))
		if errOpen != nil {
			cleanup()
			return nil, 0, func() {}, fmt.Errorf("OpenProcess on PPID %d: %w", ppid, errOpen)
		}
		parentHandle = hParent

		ret, _, err = procUpdateProcThreadAttribute.Call(
			uintptr(unsafe.Pointer(attrList)), 0,
			uintptr(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
			uintptr(unsafe.Pointer(&parentHandle)),
			unsafe.Sizeof(parentHandle), 0, 0,
		)
		if ret == 0 {
			windows.CloseHandle(parentHandle)
			cleanup()
			return nil, 0, func() {}, fmt.Errorf("UpdateProcThreadAttribute (PPID): %w", err)
		}
	}

	if blockDLLs {
		mitigationPolicy := uint64(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)
		ret, _, err = procUpdateProcThreadAttribute.Call(
			uintptr(unsafe.Pointer(attrList)), 0,
			uintptr(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY),
			uintptr(unsafe.Pointer(&mitigationPolicy)),
			unsafe.Sizeof(mitigationPolicy), 0, 0,
		)
		if ret == 0 {
			if parentHandle != 0 {
				windows.CloseHandle(parentHandle)
			}
			cleanup()
			return nil, 0, func() {}, fmt.Errorf("UpdateProcThreadAttribute (BlockDLLs): %w", err)
		}
	}

	return attrList, parentHandle, cleanup, nil
}
