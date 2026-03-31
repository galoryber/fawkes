//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
	"golang.org/x/sys/windows"
)

// --- Action: shares (local) ---

func netEnumLocalShares() structs.CommandResult {
	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32

	ret, _, _ := procNetShareEnum.Call(
		0, 2,
		uintptr(unsafe.Pointer(&buf)),
		uintptr(MAX_PREFERRED_LEN),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)

	if ret != NERR_Success && ret != ERROR_MORE_DATA {
		return errorf("Error enumerating local shares: NetShareEnum returned %d %s", ret, netApiErrorDesc(ret))
	}

	if buf == 0 || entriesRead == 0 {
		return successResult("[]")
	}
	defer procNetApiBufferFree.Call(buf)

	entries := unsafe.Slice((*shareInfo2)(unsafe.Pointer(buf)), entriesRead)
	var out []netEnumEntry

	for _, entry := range entries {
		e := netEnumEntry{Type: "share"}
		if entry.Name != nil {
			e.Name = windows.UTF16PtrToString(entry.Name)
		}
		if entry.Path != nil {
			e.Path = windows.UTF16PtrToString(entry.Path)
		}
		if entry.Remark != nil {
			e.Comment = windows.UTF16PtrToString(entry.Remark)
		}
		e.Source = neDescribeShareType(entry.Type)
		out = append(out, e)
	}

	data, _ := json.Marshal(out)
	return successResult(string(data))
}

// --- Action: shares (remote, when target is specified) ---

func netEnumRemoteShares(target string) structs.CommandResult {
	serverName := target
	if !strings.HasPrefix(serverName, "\\\\") {
		serverName = "\\\\" + serverName
	}

	serverPtr, _ := syscall.UTF16PtrFromString(serverName)

	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32

	ret, _, _ := procNetShareEnum.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		1,
		uintptr(unsafe.Pointer(&buf)),
		uintptr(MAX_PREFERRED_LEN),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)

	if ret != NERR_Success && ret != ERROR_MORE_DATA {
		return errorf("Error enumerating shares on %s: NetShareEnum returned %d %s", target, ret, netApiErrorDesc(ret))
	}

	if buf == 0 || entriesRead == 0 {
		return successResult("[]")
	}
	defer procNetApiBufferFree.Call(buf)

	entries := unsafe.Slice((*shareInfo1)(unsafe.Pointer(buf)), entriesRead)
	var out []netEnumEntry

	for _, entry := range entries {
		e := netEnumEntry{Type: "share", Server: target}
		if entry.Name != nil {
			e.Name = windows.UTF16PtrToString(entry.Name)
		}
		if entry.Remark != nil {
			e.Comment = windows.UTF16PtrToString(entry.Remark)
		}
		e.Source = neDescribeShareType(entry.Type)
		out = append(out, e)
	}

	data, _ := json.Marshal(out)
	return successResult(string(data))
}

// --- Action: mapped ---

func netEnumMappedDrives() structs.CommandResult {
	var handle syscall.Handle

	ret, _, _ := procWNetOpenEnum.Call(
		uintptr(RESOURCE_CONNECTED),
		uintptr(RESOURCETYPE_DISK),
		0, 0,
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != NERR_Success {
		return errorf("Error opening network drive enumeration: WNetOpenEnum returned %d %s", ret, netApiErrorDesc(ret))
	}
	defer procWNetCloseEnum.Call(uintptr(handle))

	var out []netEnumEntry
	bufSize := uint32(16384)
	buf := make([]byte, bufSize)

	for {
		entries := uint32(0xFFFFFFFF)
		currentBufSize := bufSize
		enumRet, _, _ := procWNetEnumRes.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&entries)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&currentBufSize)),
		)

		if enumRet != NERR_Success && enumRet != ERROR_MORE_DATA {
			break
		}

		ptr := unsafe.Pointer(&buf[0])
		resSize := unsafe.Sizeof(netResource{})
		for i := uint32(0); i < entries; i++ {
			res := (*netResource)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*resSize))
			e := netEnumEntry{Type: "mapped"}
			if res.LocalName != nil {
				e.Name = windows.UTF16PtrToString(res.LocalName)
			}
			if res.RemoteName != nil {
				e.Path = windows.UTF16PtrToString(res.RemoteName)
			}
			if res.Provider != nil {
				e.Provider = windows.UTF16PtrToString(res.Provider)
			}
			out = append(out, e)
		}

		if enumRet != ERROR_MORE_DATA {
			break
		}
	}

	if len(out) == 0 {
		return successResult("[]")
	}

	data, _ := json.Marshal(out)
	return successResult(string(data))
}
