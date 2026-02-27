//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi32              = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumSessionsW  = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionW  = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemoryWho  = wtsapi32.NewProc("WTSFreeMemory")
)

const (
	wtsActive       = 0
	wtsConnected    = 1
	wtsDisconnected = 4
	wtsIdle         = 5

	wtsUserName     = 5
	wtsDomainName   = 7
	wtsClientName   = 10
	wtsSessionInfo  = 24
	wtsConnectTime  = 25 //nolint:unused // reserved for future use
)

type wtsSessionInfoW struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

func whoPlatform(args whoArgs) string {
	var pSessionInfo uintptr
	var count uint32

	ret, _, _ := procWTSEnumSessionsW.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		0,
		1,
		uintptr(unsafe.Pointer(&pSessionInfo)),
		uintptr(unsafe.Pointer(&count)),
	)
	if ret == 0 {
		return "Error: WTSEnumerateSessionsW failed"
	}
	defer procWTSFreeMemoryWho.Call(pSessionInfo)

	var sb strings.Builder
	sb.WriteString(whoHeader())

	sessionSize := unsafe.Sizeof(wtsSessionInfoW{})
	activeCount := 0

	for i := uint32(0); i < count; i++ {
		session := (*wtsSessionInfoW)(unsafe.Pointer(pSessionInfo + uintptr(i)*sessionSize))

		// Filter to active/disconnected sessions unless -all
		if !args.All && session.State != wtsActive && session.State != wtsDisconnected {
			continue
		}

		user := wtsQueryString(session.SessionID, wtsUserName)
		if user == "" && !args.All {
			continue
		}

		domain := wtsQueryString(session.SessionID, wtsDomainName)
		client := wtsQueryString(session.SessionID, wtsClientName)

		stationName := ""
		if session.WinStationName != nil {
			stationName = windows.UTF16PtrToString(session.WinStationName)
		}

		fullUser := user
		if domain != "" {
			fullUser = domain + "\\" + user
		}

		status := wtsStateName(session.State)
		loginTime := wtsQueryConnectTime(session.SessionID)

		from := client
		if from == "" {
			from = "local"
		}

		sb.WriteString(whoEntry(fullUser, stationName, loginTime, from, status))
		activeCount++
	}

	if activeCount == 0 {
		return "No active user sessions found"
	}

	sb.WriteString(fmt.Sprintf("\n[*] %d session(s)", activeCount))
	return sb.String()
}

func wtsQueryString(sessionID uint32, infoClass int) string {
	var buf *uint16
	var bytesReturned uint32

	ret, _, _ := procWTSQuerySessionW.Call(
		0,
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ret == 0 || buf == nil {
		return ""
	}
	defer procWTSFreeMemoryWho.Call(uintptr(unsafe.Pointer(buf)))

	return windows.UTF16PtrToString(buf)
}

func wtsQueryConnectTime(sessionID uint32) string {
	var buf *byte
	var bytesReturned uint32

	ret, _, _ := procWTSQuerySessionW.Call(
		0,
		uintptr(sessionID),
		uintptr(wtsSessionInfo),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ret == 0 || buf == nil {
		return "-"
	}
	defer procWTSFreeMemoryWho.Call(uintptr(unsafe.Pointer(buf)))

	// WTSINFO struct: ConnectTime is a LARGE_INTEGER (FILETIME) at offset 0
	if bytesReturned < 8 {
		return "-"
	}

	ft := (*windows.Filetime)(unsafe.Pointer(buf))
	if ft.HighDateTime == 0 && ft.LowDateTime == 0 {
		return "-"
	}
	t := time.Unix(0, ft.Nanoseconds())
	return t.Format("2006-01-02 15:04:05")
}

func wtsStateName(state uint32) string {
	switch state {
	case wtsActive:
		return "active"
	case wtsConnected:
		return "connected"
	case wtsDisconnected:
		return "disconnected"
	case wtsIdle:
		return "idle"
	default:
		return fmt.Sprintf("state=%d", state)
	}
}
