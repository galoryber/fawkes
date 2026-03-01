//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
	"golang.org/x/sys/windows"
)

type NetSharesCommand struct{}

func (c *NetSharesCommand) Name() string {
	return "net-shares"
}

func (c *NetSharesCommand) Description() string {
	return "Enumerate network shares and mapped drives via Win32 API"
}

type netSharesArgs struct {
	Action string `json:"action"`
	Target string `json:"target"`
}

var (
	netapi32NS          = windows.NewLazySystemDLL("netapi32.dll")
	mprNS               = windows.NewLazySystemDLL("mpr.dll")
	procNetShareEnum    = netapi32NS.NewProc("NetShareEnum")
	procNetApiBufFreeNS = netapi32NS.NewProc("NetApiBufferFree")
	procWNetOpenEnum    = mprNS.NewProc("WNetOpenEnumW")
	procWNetEnumRes     = mprNS.NewProc("WNetEnumResourceW")
	procWNetCloseEnum   = mprNS.NewProc("WNetCloseEnum")
)

const (
	STYPE_DISKTREE  = 0x00000000
	STYPE_PRINTQ    = 0x00000001
	STYPE_DEVICE    = 0x00000002
	STYPE_IPC       = 0x00000003
	STYPE_SPECIAL   = 0x80000000
	STYPE_TEMPORARY = 0x40000000
	STYPE_MASK      = 0x000000FF

	// WNet resource types
	RESOURCETYPE_DISK  = 0x00000001
	RESOURCE_CONNECTED = 0x00000001
)

// SHARE_INFO_2 structure
type shareInfo2 struct {
	Name        *uint16
	Type        uint32
	Remark      *uint16
	Permissions uint32
	MaxUses     uint32
	CurrentUses uint32
	Path        *uint16
	Passwd      *uint16
}

// SHARE_INFO_1 structure (for remote shares — no path/permissions)
type shareInfo1 struct {
	Name   *uint16
	Type   uint32
	Remark *uint16
}

// NETRESOURCE structure for WNet functions
type netResource struct {
	Scope       uint32
	Type        uint32
	DisplayType uint32
	Usage       uint32
	LocalName   *uint16
	RemoteName  *uint16
	Comment     *uint16
	Provider    *uint16
}

type shareOutputEntry struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Path     string `json:"path,omitempty"`
	Remark   string `json:"remark,omitempty"`
	Host     string `json:"host,omitempty"`
	Provider string `json:"provider,omitempty"`
}

func (c *NetSharesCommand) Execute(task structs.Task) structs.CommandResult {
	var args netSharesArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (action). Use: local, remote, mapped",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "local":
		return netSharesLocal()
	case "remote":
		return netSharesRemote(args.Target)
	case "mapped":
		return netSharesMapped()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: local, remote, mapped", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func netSharesLocal() structs.CommandResult {
	var buf uintptr
	var entriesRead, totalEntries uint32
	var resumeHandle uint32

	ret, _, _ := procNetShareEnum.Call(
		0, // local server
		2, // level 2 (SHARE_INFO_2 — includes path)
		uintptr(unsafe.Pointer(&buf)),
		uintptr(MAX_PREFERRED_LEN),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)

	if ret != NERR_Success && ret != ERROR_MORE_DATA {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating local shares: NetShareEnum returned %d", ret),
			Status:    "error",
			Completed: true,
		}
	}

	if buf == 0 || entriesRead == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}
	defer procNetApiBufFreeNS.Call(buf)

	entries := unsafe.Slice((*shareInfo2)(unsafe.Pointer(buf)), entriesRead)
	var out []shareOutputEntry

	for _, entry := range entries {
		e := shareOutputEntry{}
		if entry.Name != nil {
			e.Name = windows.UTF16PtrToString(entry.Name)
		}
		if entry.Path != nil {
			e.Path = windows.UTF16PtrToString(entry.Path)
		}
		if entry.Remark != nil {
			e.Remark = windows.UTF16PtrToString(entry.Remark)
		}
		e.Type = describeShareType(entry.Type)
		out = append(out, e)
	}

	data, _ := json.Marshal(out)
	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}

func netSharesRemote(target string) structs.CommandResult {
	if target == "" {
		return structs.CommandResult{
			Output:    "Error: target (hostname or IP) is required for remote action",
			Status:    "error",
			Completed: true,
		}
	}

	// Ensure target has UNC prefix for the server name
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
		1, // level 1 (SHARE_INFO_1 — name, type, remark; doesn't need admin)
		uintptr(unsafe.Pointer(&buf)),
		uintptr(MAX_PREFERRED_LEN),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)

	if ret != NERR_Success && ret != ERROR_MORE_DATA {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating shares on %s: NetShareEnum returned %d", target, ret),
			Status:    "error",
			Completed: true,
		}
	}

	if buf == 0 || entriesRead == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}
	defer procNetApiBufFreeNS.Call(buf)

	entries := unsafe.Slice((*shareInfo1)(unsafe.Pointer(buf)), entriesRead)
	var out []shareOutputEntry

	for _, entry := range entries {
		e := shareOutputEntry{Host: target}
		if entry.Name != nil {
			e.Name = windows.UTF16PtrToString(entry.Name)
		}
		if entry.Remark != nil {
			e.Remark = windows.UTF16PtrToString(entry.Remark)
		}
		e.Type = describeShareType(entry.Type)
		out = append(out, e)
	}

	data, _ := json.Marshal(out)
	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}

func netSharesMapped() structs.CommandResult {
	// Use WNetOpenEnum/WNetEnumResource to list connected network drives
	var handle syscall.Handle

	ret, _, _ := procWNetOpenEnum.Call(
		uintptr(RESOURCE_CONNECTED),
		uintptr(RESOURCETYPE_DISK),
		0, // enumerate all
		0, // NULL (top-level)
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != NERR_Success {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening network drive enumeration: WNetOpenEnum returned %d", ret),
			Status:    "error",
			Completed: true,
		}
	}
	defer procWNetCloseEnum.Call(uintptr(handle))

	var out []shareOutputEntry
	bufSize := uint32(16384)
	buf := make([]byte, bufSize)

	for {
		entries := uint32(0xFFFFFFFF) // as many as possible
		currentBufSize := bufSize
		enumRet, _, _ := procWNetEnumRes.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&entries)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&currentBufSize)),
		)

		if enumRet != NERR_Success && enumRet != ERROR_MORE_DATA {
			break // ERROR_NO_MORE_ITEMS (259) or other — done
		}

		// Parse NETRESOURCE entries from the buffer
		ptr := unsafe.Pointer(&buf[0])
		resSize := unsafe.Sizeof(netResource{})
		for i := uint32(0); i < entries; i++ {
			res := (*netResource)(unsafe.Pointer(uintptr(ptr) + uintptr(i)*resSize))
			e := shareOutputEntry{Type: "Mapped"}
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
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	data, _ := json.Marshal(out)
	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}

func describeShareType(stype uint32) string {
	baseType := stype & STYPE_MASK
	special := stype&STYPE_SPECIAL != 0

	var typeName string
	switch baseType {
	case STYPE_DISKTREE:
		typeName = "Disk"
	case STYPE_PRINTQ:
		typeName = "Print"
	case STYPE_DEVICE:
		typeName = "Device"
	case STYPE_IPC:
		typeName = "IPC"
	default:
		typeName = fmt.Sprintf("0x%x", baseType)
	}

	if special {
		typeName += " (Admin)"
	}
	if stype&STYPE_TEMPORARY != 0 {
		typeName += " (Temp)"
	}

	return typeName
}
