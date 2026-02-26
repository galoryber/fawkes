//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"
	"golang.org/x/sys/windows"
)

type NetLocalGroupCommand struct{}

func (c *NetLocalGroupCommand) Name() string {
	return "net-localgroup"
}

func (c *NetLocalGroupCommand) Description() string {
	return "Enumerate local groups and their members on local or remote hosts via NetLocalGroup APIs"
}

type netLocalGroupArgs struct {
	Action string `json:"action"`
	Group  string `json:"group"`
	Server string `json:"server"`
}

// localGroupMembersInfo2 provides SID usage type (user vs group vs well-known)
type localGroupMembersInfo2 struct {
	SID           uintptr
	SIDUsage      uint32
	DomainAndName *uint16
}

func (c *NetLocalGroupCommand) Execute(task structs.Task) structs.CommandResult {
	var args netLocalGroupArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch args.Action {
	case "list":
		return nlgList(args.Server)
	case "members":
		return nlgMembers(args.Group, args.Server)
	case "admins":
		return nlgMembers("Administrators", args.Server)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'list', 'members', or 'admins')", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func nlgGetServerPtr(server string) (*uint16, error) {
	if server == "" {
		return nil, nil
	}
	if !strings.HasPrefix(server, "\\\\") {
		server = "\\\\" + server
	}
	return windows.UTF16PtrFromString(server)
}

// nlgList enumerates all local groups on the specified server (or local machine).
// Reuses procNetLocalGroupEnum, localGroupInfo1, etc. from netenum.go.
func nlgList(server string) structs.CommandResult {
	serverPtr, err := nlgGetServerPtr(server)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var buf uintptr
	var entriesRead, totalEntries uint32

	ret, _, _ := procNetLocalGroupEnum.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		1, // level 1 (name + comment)
		uintptr(unsafe.Pointer(&buf)),
		MAX_PREFERRED_LEN,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		0,
	)
	if ret != NERR_Success && ret != ERROR_MORE_DATA {
		return structs.CommandResult{
			Output:    fmt.Sprintf("NetLocalGroupEnum failed with error %d", ret),
			Status:    "error",
			Completed: true,
		}
	}
	if buf != 0 {
		defer procNetApiBufferFree.Call(buf)
	}

	var sb strings.Builder
	target := "localhost"
	if server != "" {
		target = server
	}
	sb.WriteString(fmt.Sprintf("Local Groups on %s: %d\n\n", target, entriesRead))

	entrySize := unsafe.Sizeof(localGroupInfo1{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*localGroupInfo1)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		name := windows.UTF16PtrToString(entry.Name)
		comment := ""
		if entry.Comment != nil {
			comment = windows.UTF16PtrToString(entry.Comment)
		}
		if comment != "" {
			sb.WriteString(fmt.Sprintf("  %-35s %s\n", name, comment))
		} else {
			sb.WriteString(fmt.Sprintf("  %s\n", name))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// nlgMembers enumerates members of a specific local group with SID type info
func nlgMembers(group, server string) structs.CommandResult {
	if group == "" {
		return structs.CommandResult{
			Output:    "Error: group parameter is required for members action",
			Status:    "error",
			Completed: true,
		}
	}

	serverPtr, err := nlgGetServerPtr(server)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	groupPtr, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var buf uintptr
	var entriesRead, totalEntries uint32

	// Use level 2 for SID usage type
	ret, _, _ := procNetLocalGroupGetMem.Call(
		uintptr(unsafe.Pointer(serverPtr)),
		uintptr(unsafe.Pointer(groupPtr)),
		2,
		uintptr(unsafe.Pointer(&buf)),
		MAX_PREFERRED_LEN,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		0,
	)
	if ret != NERR_Success && ret != ERROR_MORE_DATA {
		return structs.CommandResult{
			Output:    fmt.Sprintf("NetLocalGroupGetMembers failed with error %d (group: %s)", ret, group),
			Status:    "error",
			Completed: true,
		}
	}
	if buf != 0 {
		defer procNetApiBufferFree.Call(buf)
	}

	var sb strings.Builder
	target := "localhost"
	if server != "" {
		target = server
	}
	sb.WriteString(fmt.Sprintf("Members of %s\\%s: %d\n\n", target, group, entriesRead))

	entrySize := unsafe.Sizeof(localGroupMembersInfo2{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*localGroupMembersInfo2)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		name := ""
		if entry.DomainAndName != nil {
			name = windows.UTF16PtrToString(entry.DomainAndName)
		}
		sidType := nlgSidUsageString(entry.SIDUsage)
		sb.WriteString(fmt.Sprintf("  %-45s  %s\n", name, sidType))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func nlgSidUsageString(usage uint32) string {
	switch usage {
	case 1:
		return "User"
	case 2:
		return "Group"
	case 3:
		return "Domain"
	case 4:
		return "Alias"
	case 5:
		return "WellKnownGroup"
	case 6:
		return "DeletedAccount"
	case 9:
		return "Computer"
	default:
		return fmt.Sprintf("Type(%d)", usage)
	}
}
