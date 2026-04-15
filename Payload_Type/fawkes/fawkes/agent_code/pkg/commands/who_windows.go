//go:build windows
// +build windows

package commands

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WTS info class constants for who command
const (
	whoWTSActive       = 0
	whoWTSConnected    = 1
	whoWTSDisconnected = 4
	whoWTSIdle         = 5

	whoWTSUserName    = 5
	whoWTSDomainName  = 7
	whoWTSClientName  = 10
	whoWTSSessionInfo = 24
)

func whoPlatform(args whoArgs) []whoSessionEntry {
	var pSessionInfo uintptr
	var count uint32

	ret, _, _ := procWTSEnumSess.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		0,
		1,
		uintptr(unsafe.Pointer(&pSessionInfo)),
		uintptr(unsafe.Pointer(&count)),
	)
	if ret == 0 {
		return nil
	}
	defer procWTSFreeMemory.Call(pSessionInfo)

	sessionSize := unsafe.Sizeof(wtsSessionInfoW{})
	var entries []whoSessionEntry

	for i := uint32(0); i < count; i++ {
		session := (*wtsSessionInfoW)(unsafe.Pointer(pSessionInfo + uintptr(i)*sessionSize))

		if !args.All && session.State != whoWTSActive && session.State != whoWTSDisconnected {
			continue
		}

		user := whoQueryString(session.SessionId, whoWTSUserName)
		if user == "" && !args.All {
			continue
		}

		domain := whoQueryString(session.SessionId, whoWTSDomainName)
		client := whoQueryString(session.SessionId, whoWTSClientName)

		stationName := ""
		if session.WinStationName != nil {
			stationName = windows.UTF16PtrToString(session.WinStationName)
		}

		fullUser := user
		if domain != "" {
			fullUser = domain + "\\" + user
		}

		status := whoStateName(session.State)
		loginTime := whoQueryConnectTime(session.SessionId)

		from := client
		if from == "" {
			from = "local"
		}

		entries = append(entries, whoSessionEntry{
			User:      fullUser,
			TTY:       stationName,
			LoginTime: loginTime,
			From:      from,
			Status:    status,
		})
	}

	return entries
}

func whoQueryString(sessionID uint32, infoClass int) string {
	var buf *uint16
	var bytesReturned uint32

	ret, _, _ := procWTSQuerySess.Call(
		0,
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ret == 0 || buf == nil {
		return ""
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))

	return windows.UTF16PtrToString(buf)
}

func whoQueryConnectTime(sessionID uint32) string {
	var buf *byte
	var bytesReturned uint32

	ret, _, _ := procWTSQuerySess.Call(
		0,
		uintptr(sessionID),
		uintptr(whoWTSSessionInfo),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ret == 0 || buf == nil {
		return "-"
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))

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

func whoStateName(state uint32) string {
	switch state {
	case whoWTSActive:
		return "active"
	case whoWTSConnected:
		return "connected"
	case whoWTSDisconnected:
		return "disconnected"
	case whoWTSIdle:
		return "idle"
	default:
		return fmt.Sprintf("state=%d", state)
	}
}
