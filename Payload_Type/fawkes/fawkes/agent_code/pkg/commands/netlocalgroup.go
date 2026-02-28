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

// nlgGroupEntry represents a local group for JSON output
type nlgGroupEntry struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
	Server  string `json:"server,omitempty"`
}

// nlgMemberEntry represents a local group member for JSON output
type nlgMemberEntry struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Group   string `json:"group"`
	Server  string `json:"server,omitempty"`
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

	var entries []nlgGroupEntry
	entrySize := unsafe.Sizeof(localGroupInfo1{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*localGroupInfo1)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		name := windows.UTF16PtrToString(entry.Name)
		comment := ""
		if entry.Comment != nil {
			comment = windows.UTF16PtrToString(entry.Comment)
		}
		entries = append(entries, nlgGroupEntry{
			Name:    name,
			Comment: comment,
			Server:  server,
		})
	}

	if len(entries) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling results: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(data),
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

	var entries []nlgMemberEntry
	entrySize := unsafe.Sizeof(localGroupMembersInfo2{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*localGroupMembersInfo2)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		name := ""
		if entry.DomainAndName != nil {
			name = windows.UTF16PtrToString(entry.DomainAndName)
		}
		entries = append(entries, nlgMemberEntry{
			Name:   name,
			Type:   nlgSidUsageString(entry.SIDUsage),
			Group:  group,
			Server: server,
		})
	}

	if len(entries) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling results: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(data),
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
