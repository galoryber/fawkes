//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"fawkes/pkg/structs"
	"golang.org/x/sys/windows"
)

// --- Action: loggedon ---

func netEnumLoggedOn(target string) structs.CommandResult {
	var serverPtr uintptr
	if target != "" {
		serverName, err := windows.UTF16PtrFromString(`\\` + target)
		if err != nil {
			return errorf("Error: %v", err)
		}
		serverPtr = uintptr(unsafe.Pointer(serverName))
	}

	var buf uintptr
	var entriesRead, totalEntries, resumeHandle uint32

	ret, _, _ := procNetWkstaUserEnum.Call(
		serverPtr,
		1,
		uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if buf != 0 {
		defer procNetApiBufferFree.Call(buf)
	}

	if ret != 0 {
		return errorf("NetWkstaUserEnum failed: error %d", ret)
	}

	if entriesRead == 0 {
		return successResult("[]")
	}

	var entries []netEnumEntry
	entrySize := unsafe.Sizeof(wkstaUserInfo1{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*wkstaUserInfo1)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		entries = append(entries, netEnumEntry{
			Name:   neWideToString(entry.Username),
			Domain: neWideToString(entry.LogonDomain),
			Server: neWideToString(entry.LogonServer),
			Type:   "loggedon",
		})
	}

	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// --- Action: sessions ---

func netEnumSessions(target string) structs.CommandResult {
	// Try level 502 first (more detail, requires admin)
	output, err := neEnumSessions502(target)
	if err != nil {
		// Fall back to level 10 (less detail, no admin required)
		output, err = neEnumSessions10(target)
		if err != nil {
			return errorf("Error enumerating sessions: %v", err)
		}
	}
	return successResult(output)
}

func neEnumSessions502(target string) (string, error) {
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
		serverPtr, 0, 0, 502,
		uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if buf != 0 {
		defer procNetApiBufferFree.Call(buf)
	}
	if ret != 0 {
		return "", fmt.Errorf("NetSessionEnum level 502 failed: error %d", ret)
	}
	if entriesRead == 0 {
		return "[]", nil
	}

	var entries []netEnumEntry
	entrySize := unsafe.Sizeof(sessionInfo502{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*sessionInfo502)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		entries = append(entries, netEnumEntry{
			Client:    neWideToString(entry.ClientName),
			Name:      neWideToString(entry.UserName),
			Opens:     int(entry.NumOpens),
			Time:      neFormatDuration(entry.Time),
			Idle:      neFormatDuration(entry.IdleTime),
			Transport: neWideToString(entry.ClientType),
			Type:      "session",
		})
	}

	data, _ := json.Marshal(entries)
	return string(data), nil
}

func neEnumSessions10(target string) (string, error) {
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
		serverPtr, 0, 0, 10,
		uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if buf != 0 {
		defer procNetApiBufferFree.Call(buf)
	}
	if ret != 0 {
		return "", fmt.Errorf("NetSessionEnum level 10 failed: error %d", ret)
	}
	if entriesRead == 0 {
		return "[]", nil
	}

	var entries []netEnumEntry
	entrySize := unsafe.Sizeof(sessionInfo10{})
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*sessionInfo10)(unsafe.Pointer(buf + uintptr(i)*entrySize))
		entries = append(entries, netEnumEntry{
			Client: neWideToString(entry.ClientName),
			Name:   neWideToString(entry.UserName),
			Time:   neFormatDuration(entry.Time),
			Idle:   neFormatDuration(entry.IdleTime),
			Type:   "session",
		})
	}

	data, _ := json.Marshal(entries)
	return string(data), nil
}
