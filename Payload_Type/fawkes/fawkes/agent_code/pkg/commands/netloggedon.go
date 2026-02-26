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

var (
	netapi32Logon           = windows.NewLazySystemDLL("netapi32.dll")
	procNetWkstaUserEnum    = netapi32Logon.NewProc("NetWkstaUserEnum")
	procNetApiBufFreeLogon  = netapi32Logon.NewProc("NetApiBufferFree")
)

type NetLoggedonCommand struct{}

func (c *NetLoggedonCommand) Name() string        { return "net-loggedon" }
func (c *NetLoggedonCommand) Description() string { return "Enumerate logged-on users on local or remote hosts (T1033)" }

type netLoggedonArgs struct {
	Target string `json:"target"`
}

// WKSTA_USER_INFO_1 structure
type wkstaUserInfo1 struct {
	Username    uintptr // LPWSTR
	LogonDomain uintptr // LPWSTR
	OtherDomains uintptr // LPWSTR
	LogonServer uintptr // LPWSTR
}

func (c *NetLoggedonCommand) Execute(task structs.Task) structs.CommandResult {
	var args netLoggedonArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	output, err := enumerateLoggedOn(args.Target)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating logged-on users: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func enumerateLoggedOn(target string) (string, error) {
	var serverPtr uintptr
	if target != "" {
		serverName, err := windows.UTF16PtrFromString(`\\` + target)
		if err != nil {
			return "", err
		}
		serverPtr = uintptr(unsafe.Pointer(serverName))
	}

	var buf uintptr
	var entriesRead, totalEntries, resumeHandle uint32

	ret, _, _ := procNetWkstaUserEnum.Call(
		serverPtr,
		1, // level 1 — includes logon domain and logon server
		uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF, // MAX_PREFERRED_LENGTH
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if buf != 0 {
		defer procNetApiBufFreeLogon.Call(buf)
	}

	if ret != 0 {
		return "", fmt.Errorf("NetWkstaUserEnum failed: error %d", ret)
	}

	var sb strings.Builder
	targetDisplay := target
	if targetDisplay == "" {
		targetDisplay = "(local)"
	}
	sb.WriteString(fmt.Sprintf("Logged-On Users on %s\n", targetDisplay))
	sb.WriteString(fmt.Sprintf("Total: %d users\n", totalEntries))
	sb.WriteString(strings.Repeat("=", 70) + "\n")

	if entriesRead == 0 {
		sb.WriteString("\nNo logged-on users found.\n")
		return sb.String(), nil
	}

	sb.WriteString(fmt.Sprintf("\n%-25s %-20s %s\n", "Username", "Logon Domain", "Logon Server"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	entrySize := unsafe.Sizeof(wkstaUserInfo1{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*wkstaUserInfo1)(unsafe.Pointer(buf + uintptr(i)*entrySize))

		username := logonWideToString(entry.Username)
		domain := logonWideToString(entry.LogonDomain)
		server := logonWideToString(entry.LogonServer)

		sb.WriteString(fmt.Sprintf("%-25s %-20s %s\n", username, domain, server))
	}

	return sb.String(), nil
}

// logonWideToString converts a Windows LPWSTR to a Go string
func logonWideToString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var chars []uint16
	for i := uintptr(0); ; i += 2 {
		ch := *(*uint16)(unsafe.Pointer(ptr + i))
		if ch == 0 {
			break
		}
		chars = append(chars, ch)
		if i > 1024 {
			break
		}
	}
	return windows.UTF16ToString(chars)
}
