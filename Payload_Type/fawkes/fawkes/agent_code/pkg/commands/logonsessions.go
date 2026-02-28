//go:build windows

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

type LogonSessionsCommand struct{}

func (c *LogonSessionsCommand) Name() string {
	return "logonsessions"
}

func (c *LogonSessionsCommand) Description() string {
	return "Enumerate active logon sessions on the system (T1033)"
}

type logonSessionsArgs struct {
	Action string `json:"action"` // "list" (default) or "users" (unique users only)
	Filter string `json:"filter"` // Optional username filter
}

var (
	wtsapi32LS        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumSess   = wtsapi32LS.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory = wtsapi32LS.NewProc("WTSFreeMemory")
	procWTSQuerySess  = wtsapi32LS.NewProc("WTSQuerySessionInformationW")
)

// WTS_SESSION_INFO_W structure (must match 64-bit layout)
type wtsSessionInfoW struct {
	SessionId      uint32
	_              uint32 // padding for alignment
	WinStationName *uint16
	State          uint32
	_              uint32 // padding after State
}

// WTS_INFO_CLASS constants
const (
	wtsInfoClassUserName   = 5
	wtsInfoClassDomainName = 7
	wtsInfoClassClientName = 10
)

// WTS_CONNECTSTATE_CLASS constants
var wtsStateNames = map[uint32]string{
	0: "Active",
	1: "Connected",
	2: "ConnectQuery",
	3: "Shadow",
	4: "Disconnected",
	5: "Idle",
	6: "Listen",
	7: "Reset",
	8: "Down",
	9: "Init",
}

type sessionEntry struct {
	SessionID  uint32 `json:"session_id"`
	UserName   string `json:"username"`
	Domain     string `json:"domain"`
	Station    string `json:"station"`
	State      string `json:"state"`
	ClientName string `json:"client,omitempty"`
}

func (c *LogonSessionsCommand) Execute(task structs.Task) structs.CommandResult {
	var args logonSessionsArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	action := strings.ToLower(args.Action)
	if action == "" {
		action = "list"
	}

	switch action {
	case "list":
		return logonSessionsList(args)
	case "users":
		return logonSessionsUsers(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: list, users", action),
			Status:    "error",
			Completed: true,
		}
	}
}

// enumerateWTSSessions gets all WTS sessions with user info
func enumerateWTSSessions() ([]sessionEntry, error) {
	var sessionInfoPtr uintptr
	var sessionCount uint32

	ret, _, err := procWTSEnumSess.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		0, // Reserved
		1, // Version
		uintptr(unsafe.Pointer(&sessionInfoPtr)),
		uintptr(unsafe.Pointer(&sessionCount)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("WTSEnumerateSessionsW failed: %v", err)
	}
	defer procWTSFreeMemory.Call(sessionInfoPtr)

	var sessions []sessionEntry

	// Parse the array of WTS_SESSION_INFO structures
	// On 64-bit Windows, the struct is: uint32 SessionId, padding, *uint16 WinStationName, uint32 State, padding
	// Total size = 24 bytes on 64-bit
	const infoSize = 24 // sizeof(WTS_SESSION_INFO_W) on 64-bit
	for i := uint32(0); i < sessionCount; i++ {
		basePtr := sessionInfoPtr + uintptr(i)*infoSize

		sessionId := *(*uint32)(unsafe.Pointer(basePtr))
		winStationName := *(**uint16)(unsafe.Pointer(basePtr + 8))
		state := *(*uint32)(unsafe.Pointer(basePtr + 16))

		station := ""
		if winStationName != nil {
			station = syscall.UTF16ToString(utf16PtrToSlice(winStationName))
		}

		stateName := wtsStateNames[state]
		if stateName == "" {
			stateName = fmt.Sprintf("Unknown(%d)", state)
		}

		// Query username for this session
		userName := wtsQuerySessionString(sessionId, wtsInfoClassUserName)
		domain := wtsQuerySessionString(sessionId, wtsInfoClassDomainName)
		clientName := wtsQuerySessionString(sessionId, wtsInfoClassClientName)

		sessions = append(sessions, sessionEntry{
			SessionID:  sessionId,
			UserName:   userName,
			Domain:     domain,
			Station:    station,
			State:      stateName,
			ClientName: clientName,
		})
	}

	return sessions, nil
}

// wtsQuerySessionString queries a string info class for a session
func wtsQuerySessionString(sessionId uint32, infoClass uint32) string {
	var buffer uintptr
	var bytesReturned uint32

	ret, _, _ := procWTSQuerySess.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		uintptr(sessionId),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ret == 0 || buffer == 0 {
		return ""
	}
	defer procWTSFreeMemory.Call(buffer)

	if bytesReturned <= 2 { // Empty string (just null terminator)
		return ""
	}

	return syscall.UTF16ToString(utf16PtrToSlice((*uint16)(unsafe.Pointer(buffer))))
}

// utf16PtrToSlice converts a null-terminated UTF-16 pointer to a slice
func utf16PtrToSlice(p *uint16) []uint16 {
	if p == nil {
		return nil
	}
	// Walk until null terminator, max 260 chars
	var result []uint16
	for i := 0; i < 260; i++ {
		c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i)*2))
		if c == 0 {
			break
		}
		result = append(result, c)
	}
	result = append(result, 0) // null terminator for UTF16ToString
	return result
}

// logonSessionsList enumerates all sessions
func logonSessionsList(args logonSessionsArgs) structs.CommandResult {
	sessions, err := enumerateWTSSessions()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Filter
	var filtered []sessionEntry
	for _, s := range sessions {
		if args.Filter != "" {
			filterLower := strings.ToLower(args.Filter)
			if !strings.Contains(strings.ToLower(s.UserName), filterLower) &&
				!strings.Contains(strings.ToLower(s.Domain), filterLower) {
				continue
			}
		}
		filtered = append(filtered, s)
	}

	if len(filtered) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	data, err := json.Marshal(filtered)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling output: %v", err),
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

type userEntry struct {
	User     string   `json:"user"`
	Domain   string   `json:"domain,omitempty"`
	Sessions int      `json:"sessions"`
	Details  []string `json:"details"`
}

// logonSessionsUsers returns unique logged-on users
func logonSessionsUsers(args logonSessionsArgs) structs.CommandResult {
	sessions, err := enumerateWTSSessions()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	type userInfo struct {
		Domain   string
		Sessions map[uint32]string
	}

	users := make(map[string]*userInfo)

	for _, s := range sessions {
		if s.UserName == "" {
			continue
		}

		if args.Filter != "" {
			filterLower := strings.ToLower(args.Filter)
			if !strings.Contains(strings.ToLower(s.UserName), filterLower) &&
				!strings.Contains(strings.ToLower(s.Domain), filterLower) {
				continue
			}
		}

		key := s.UserName
		if s.Domain != "" {
			key = s.Domain + "\\" + s.UserName
		}

		if entry, ok := users[key]; ok {
			entry.Sessions[s.SessionID] = s.State
		} else {
			users[key] = &userInfo{
				Domain:   s.Domain,
				Sessions: map[uint32]string{s.SessionID: s.State},
			}
		}
	}

	if len(users) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	var entries []userEntry
	for name, info := range users {
		var details []string
		for sid, state := range info.Sessions {
			details = append(details, fmt.Sprintf("%d(%s)", sid, state))
		}
		entries = append(entries, userEntry{
			User:     name,
			Domain:   info.Domain,
			Sessions: len(info.Sessions),
			Details:  details,
		})
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling output: %v", err),
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

