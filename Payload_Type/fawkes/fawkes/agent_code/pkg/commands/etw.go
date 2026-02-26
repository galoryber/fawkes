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
	return "Enumerate ETW trace sessions and providers to assess security telemetry coverage"
}

type etwParams struct {
	Action string `json:"action"`
}

var (
	advapi32ETW                 = windows.NewLazySystemDLL("advapi32.dll")
	procQueryAllTracesW         = advapi32ETW.NewProc("QueryAllTracesW")
	procEnumerateTraceGuidsEx   = advapi32ETW.NewProc("EnumerateTraceGuidsEx")
)

// EVENT_TRACE_PROPERTIES structure (simplified)
// Minimum size needed for QueryAllTracesW
const eventTracePropsSize = 1024

// TRACE_QUERY_INFO_CLASS values
const (
	traceGuidQueryList = 0
	traceGuidQueryInfo = 1
)

// Well-known ETW provider GUIDs for security tools
var knownSecurityProviders = map[string]string{
	"54849625-5478-4994-A5BA-3E3B0328C30D": "Microsoft-Windows-Security-Auditing",
	"EDD08927-9CC4-4E65-B970-C2560FB5C289": "Microsoft-Windows-Kernel-Process",
	"22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716": "Microsoft-Windows-Kernel-File",
	"A68CA8B7-004F-D7B6-A698-04740076C4E7": "Microsoft-Windows-Kernel-Network",
	"0BD3506A-9030-4F76-B16D-2803530B31F1": "Microsoft-Windows-Kernel-Registry",
	"DCBE5AAA-16E2-457C-9337-366950045F0A": "Microsoft-Windows-WMI-Activity",
	"7DD42A49-5329-4832-8DFD-43D979153A88": "Microsoft-Windows-Kernel-Audit-API-Calls",
	"B675EC37-BDB6-4648-BC92-F3FDC74D3CA2": "Microsoft-Windows-LDAP-Client",
	"F4E1897A-BB65-5399-F245-102D38640FFE": "Microsoft-Antimalware-Scan-Interface",
	"A0C1853B-5C40-4B15-8766-3CF1C58F985A": "Microsoft-Windows-PowerShell",
	"11C5D8AD-756A-42C2-8087-EB1B4A72A846": "Microsoft-Windows-WinRM",
	"F4190177-63B0-4CB5-8B2C-3A5C3D319B6D": "Microsoft-Windows-CAPI2",
	"DBE9B383-7CF3-4331-91CC-A3CB16A3B538": "Microsoft-Windows-Winlogon",
	"0CCE985E-0000-0000-0000-000000000000": "Microsoft-Windows-Security-Auditing-Process",
	"E8109B99-3A2C-4961-AA83-D1A7A148ADA8": "Microsoft-Windows-TaskScheduler",
	"B3A7698A-0C45-44DA-B73D-E181C9B5C8E6": "Microsoft-Windows-Sysmon",
	"555908D1-A6D7-4695-8E1E-26931D2012F4": "Microsoft-Windows-DNS-Client",
	"A83D4C09-79AF-4A78-A129-A15ECCAE1BF9": "Microsoft-Windows-RPC",
	"04C2CAB3-2A99-4097-AB1C-1291F8EB6E95": "Microsoft-Windows-DotNETRuntime",
}

func (c *EtwCommand) Execute(task structs.Task) structs.CommandResult {
	var params etwParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.Action == "" {
		params.Action = "sessions"
	}

	switch params.Action {
	case "sessions":
		return etwSessions()
	case "providers":
		return etwProviders()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'sessions' or 'providers')", params.Action),
			Status:    "error",
			Completed: true,
		}
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
		propsPtrs[i] = uintptr(unsafe.Pointer(&propsBufs[i][0]))
	}

	var sessionCount uint32
	r1, _, err := procQueryAllTracesW.Call(
		uintptr(unsafe.Pointer(&propsPtrs[0])),
		maxSessions,
		uintptr(unsafe.Pointer(&sessionCount)),
	)
	if r1 != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("QueryAllTracesW failed: %v (0x%X)", err, r1),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Active ETW Trace Sessions — %d found\n\n", sessionCount))
	sb.WriteString(fmt.Sprintf("%-35s %-8s %s\n", "SESSION NAME", "EVENTS", "SECURITY RELEVANCE"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for i := uint32(0); i < sessionCount; i++ {
		buf := propsBufs[i]

		// WNODE_HEADER: BufferSize(4) + ProviderId(4) + HistoricalContext(8) + TimeStamp(8) +
		// Guid(16) + ClientContext(4) + Flags(4) = 48 bytes
		// EVENT_TRACE_PROPERTIES after WNODE_HEADER:
		// BufferSize(4) + MinimumBuffers(4) + MaximumBuffers(4) + MaximumFileSize(4) +
		// LogFileMode(4) + FlushTimer(4) + EnableFlags(4) + ...
		// LoggerNameOffset at offset 112 (0x70)
		// LogFileNameOffset at offset 116 (0x74)

		loggerNameOffset := binary.LittleEndian.Uint32(buf[112:116])
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
			truncateStr(sessionName, 35), "", relevance))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
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
		return structs.CommandResult{
			Output:    "No ETW providers found or EnumerateTraceGuidsEx not available",
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("EnumerateTraceGuidsEx failed: %v (0x%X)", err, r1),
			Status:    "error",
			Completed: true,
		}
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func parseGUID(data []byte) windows.GUID {
	return windows.GUID{
		Data1: binary.LittleEndian.Uint32(data[0:4]),
		Data2: binary.LittleEndian.Uint16(data[4:6]),
		Data3: binary.LittleEndian.Uint16(data[6:8]),
		Data4: [8]byte{data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]},
	}
}

func classifySessionSecurity(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "defender") || strings.Contains(lower, "antimalware"):
		return "!! DEFENDER/AV"
	case strings.Contains(lower, "sysmon"):
		return "!! SYSMON"
	case strings.Contains(lower, "edr") || strings.Contains(lower, "sentinel") ||
		strings.Contains(lower, "crowdstrike") || strings.Contains(lower, "carbon"):
		return "!! EDR"
	case strings.Contains(lower, "security"):
		return "! Security"
	case strings.Contains(lower, "audit"):
		return "! Audit"
	case strings.Contains(lower, "etw") || strings.Contains(lower, "eventlog"):
		return "Telemetry"
	case strings.Contains(lower, "kernel"):
		return "Kernel"
	case strings.Contains(lower, "diagtrack") || strings.Contains(lower, "autologger"):
		return "Diagnostics"
	default:
		return ""
	}
}
