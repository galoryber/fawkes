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
	netapi32Ses         = windows.NewLazySystemDLL("netapi32.dll")
	procNetSessionEnum  = netapi32Ses.NewProc("NetSessionEnum")
	procNetApiBufFreeSes = netapi32Ses.NewProc("NetApiBufferFree")
)

type NetSessionCommand struct{}

func (c *NetSessionCommand) Name() string        { return "net-session" }
func (c *NetSessionCommand) Description() string { return "Enumerate active SMB sessions (T1049)" }

type netSessionArgs struct {
	Target string `json:"target"`
}

// SESSION_INFO_10 structure (level 10 — doesn't require admin)
type sessionInfo10 struct {
	ClientName uintptr // LPWSTR
	UserName   uintptr // LPWSTR
	Time       uint32  // seconds connected
	IdleTime   uint32  // seconds idle
}

// SESSION_INFO_502 structure (level 502 — requires admin, has transport info)
type sessionInfo502 struct {
	ClientName    uintptr // LPWSTR
	UserName      uintptr // LPWSTR
	NumOpens      uint32  // open files/resources
	Time          uint32  // seconds connected
	IdleTime      uint32  // seconds idle
	UserFlags     uint32  // user flags
	ClientType    uintptr // LPWSTR — transport name
}

func (c *NetSessionCommand) Execute(task structs.Task) structs.CommandResult {
	var args netSessionArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Try level 502 first (more detail, requires admin)
	output, err := enumerateSessions502(args.Target)
	if err != nil {
		// Fall back to level 10 (less detail, no admin required)
		output, err = enumerateSessions10(args.Target)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error enumerating sessions: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func enumerateSessions502(target string) (string, error) {
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

	ret, _, _ := procNetSessionEnum.Call(
		serverPtr,       // servername (NULL = local)
		0,               // UncClientName (NULL = all clients)
		0,               // username (NULL = all users)
		502,             // level
		uintptr(unsafe.Pointer(&buf)), // bufptr
		0xFFFFFFFF,      // prefmaxlen (MAX_PREFERRED_LENGTH)
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if buf != 0 {
		defer procNetApiBufFreeSes.Call(buf)
	}

	// NERR_Success = 0, ERROR_ACCESS_DENIED = 5
	if ret != 0 {
		return "", fmt.Errorf("NetSessionEnum level 502 failed: error %d", ret)
	}

	var sb strings.Builder
	targetDisplay := target
	if targetDisplay == "" {
		targetDisplay = "(local)"
	}
	sb.WriteString(fmt.Sprintf("SMB Sessions on %s\n", targetDisplay))
	sb.WriteString(fmt.Sprintf("Total: %d sessions\n", totalEntries))
	sb.WriteString(strings.Repeat("=", 70) + "\n")

	if entriesRead == 0 {
		sb.WriteString("\nNo active sessions.\n")
		return sb.String(), nil
	}

	sb.WriteString(fmt.Sprintf("\n%-25s %-20s %-8s %-8s %-8s %s\n", "Client", "User", "Opens", "Time", "Idle", "Transport"))
	sb.WriteString(strings.Repeat("-", 85) + "\n")

	entrySize := unsafe.Sizeof(sessionInfo502{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*sessionInfo502)(unsafe.Pointer(buf + uintptr(i)*entrySize))

		client := sesWideToString(entry.ClientName)
		user := sesWideToString(entry.UserName)
		transport := sesWideToString(entry.ClientType)

		sb.WriteString(fmt.Sprintf("%-25s %-20s %-8d %-8s %-8s %s\n",
			client, user, entry.NumOpens,
			sesFormatDuration(entry.Time), sesFormatDuration(entry.IdleTime),
			transport))
	}

	return sb.String(), nil
}

func enumerateSessions10(target string) (string, error) {
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

	ret, _, _ := procNetSessionEnum.Call(
		serverPtr,
		0,
		0,
		10, // level 10 — no admin required
		uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if buf != 0 {
		defer procNetApiBufFreeSes.Call(buf)
	}

	if ret != 0 {
		return "", fmt.Errorf("NetSessionEnum level 10 failed: error %d", ret)
	}

	var sb strings.Builder
	targetDisplay := target
	if targetDisplay == "" {
		targetDisplay = "(local)"
	}
	sb.WriteString(fmt.Sprintf("SMB Sessions on %s\n", targetDisplay))
	sb.WriteString(fmt.Sprintf("Total: %d sessions\n", totalEntries))
	sb.WriteString(strings.Repeat("=", 70) + "\n")

	if entriesRead == 0 {
		sb.WriteString("\nNo active sessions.\n")
		return sb.String(), nil
	}

	sb.WriteString(fmt.Sprintf("\n%-25s %-20s %-10s %s\n", "Client", "User", "Connected", "Idle"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	entrySize := unsafe.Sizeof(sessionInfo10{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*sessionInfo10)(unsafe.Pointer(buf + uintptr(i)*entrySize))

		client := sesWideToString(entry.ClientName)
		user := sesWideToString(entry.UserName)

		sb.WriteString(fmt.Sprintf("%-25s %-20s %-10s %s\n",
			client, user,
			sesFormatDuration(entry.Time), sesFormatDuration(entry.IdleTime)))
	}

	return sb.String(), nil
}

// sesWideToString converts a Windows LPWSTR to a Go string
func sesWideToString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	// Read UTF-16 chars until null terminator
	var chars []uint16
	for i := uintptr(0); ; i += 2 {
		ch := *(*uint16)(unsafe.Pointer(ptr + i))
		if ch == 0 {
			break
		}
		chars = append(chars, ch)
		if i > 1024 { // safety limit
			break
		}
	}
	return windows.UTF16ToString(chars)
}

// sesFormatDuration converts seconds to a human-readable duration
func sesFormatDuration(seconds uint32) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm%ds", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%dh%dm", seconds/3600, (seconds%3600)/60)
}
