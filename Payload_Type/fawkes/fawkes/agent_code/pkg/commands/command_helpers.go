package commands

// command_helpers.go contains pure helper functions extracted from
// platform-specific command files for cross-platform testing.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// --- DPAPI helpers (from dpapi.go) ---

// dpapiIsPrintable checks if a byte slice contains printable ASCII/UTF-8
func dpapiIsPrintable(data []byte) bool {
	for _, b := range data {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// isGUID checks if a string looks like a GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// extractXMLTag extracts the text content of a simple XML tag
func extractXMLTag(xml, tag string) string {
	start := strings.Index(xml, "<"+tag+">")
	if start == -1 {
		return ""
	}
	start += len(tag) + 2
	end := strings.Index(xml[start:], "</"+tag+">")
	if end == -1 {
		return ""
	}
	return xml[start : start+end]
}

// --- ETW helpers (from etw.go) ---

// classifySessionSecurity classifies an ETW session name by security relevance
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

// --- BITS helpers (from bits.go) ---

// bitsFormatBytes formats byte counts as human-readable strings
func bitsFormatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// bitsEllipsis truncates a string with ellipsis if it exceeds max length
func bitsEllipsis(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

// --- Credential Manager helpers (from credman.go) ---

// Credential type constants
const (
	credTypeGeneric           = 1
	credTypeDomainPassword    = 2
	credTypeDomainCertificate = 3
	credTypeDomainVisible     = 4
)

// isPrintable checks if a string contains only printable characters
func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return len(s) > 0
}

// credTypeName maps Windows credential type codes to display names
func credTypeName(t uint32) string {
	switch t {
	case credTypeGeneric:
		return "Generic"
	case credTypeDomainPassword:
		return "Domain Password"
	case credTypeDomainCertificate:
		return "Domain Certificate"
	case credTypeDomainVisible:
		return "Domain Visible Password"
	default:
		return fmt.Sprintf("Unknown (%d)", t)
	}
}

// credPersistName maps credential persistence scope codes to names
func credPersistName(p uint32) string {
	switch p {
	case 1:
		return "Session"
	case 2:
		return "Local Machine"
	case 3:
		return "Enterprise"
	default:
		return fmt.Sprintf("Unknown (%d)", p)
	}
}

// --- Amcache/Shimcache helpers (from amcache.go) ---

// decodeUTF16LEShim decodes a UTF-16LE byte slice to a Go string
func decodeUTF16LEShim(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	// Remove trailing null
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}

// --- Event Log helpers (from eventlog.go) ---

// extractXMLField extracts a simple element value like <EventID>4624</EventID>
// Also handles attributes: <EventID Qualifiers='0'>4624</EventID>
func extractXMLField(xml, field string) string {
	start := fmt.Sprintf("<%s>", field)
	startAlt := fmt.Sprintf("<%s ", field)
	end := fmt.Sprintf("</%s>", field)

	idx := strings.Index(xml, start)
	if idx == -1 {
		idx = strings.Index(xml, startAlt)
		if idx == -1 {
			return ""
		}
		closeIdx := strings.Index(xml[idx:], ">")
		if closeIdx == -1 {
			return ""
		}
		idx = idx + closeIdx + 1
	} else {
		idx += len(start)
	}

	endIdx := strings.Index(xml[idx:], end)
	if endIdx == -1 {
		return ""
	}
	return xml[idx : idx+endIdx]
}

// extractXMLAttr extracts an attribute value like <TimeCreated SystemTime='2025-01-01'/>
func extractXMLAttr(xml, element, attr string) string {
	elemIdx := strings.Index(xml, "<"+element)
	if elemIdx == -1 {
		return ""
	}
	rest := xml[elemIdx:]
	attrKey := attr + "='"
	attrIdx := strings.Index(rest, attrKey)
	if attrIdx == -1 {
		attrKey = attr + `="`
		attrIdx = strings.Index(rest, attrKey)
		if attrIdx == -1 {
			return ""
		}
	}
	valStart := attrIdx + len(attrKey)
	quote := attrKey[len(attrKey)-1]
	valEnd := strings.IndexByte(rest[valStart:], quote)
	if valEnd == -1 {
		return ""
	}
	return rest[valStart : valStart+valEnd]
}

// summarizeEventXML extracts key fields from event XML for compact display
func summarizeEventXML(xml string) string {
	eventID := extractXMLField(xml, "EventID")
	timeCreated := extractXMLAttr(xml, "TimeCreated", "SystemTime")
	provider := extractXMLAttr(xml, "Provider", "Name")
	level := extractXMLField(xml, "Level")

	levelName := "Info"
	switch level {
	case "1":
		levelName = "Critical"
	case "2":
		levelName = "Error"
	case "3":
		levelName = "Warning"
	case "4":
		levelName = "Info"
	case "5":
		levelName = "Verbose"
	}

	if len(timeCreated) > 19 {
		timeCreated = timeCreated[:19]
	}

	return fmt.Sprintf("%s | EventID: %s | %s | %s", timeCreated, eventID, levelName, provider)
}

// buildEventXPath builds an XPath filter for Windows event log queries
func buildEventXPath(filter string, eventID int) string {
	if filter != "" && (strings.HasPrefix(filter, "*[") || strings.HasPrefix(filter, "<QueryList")) {
		return filter
	}

	var parts []string
	if eventID > 0 {
		parts = append(parts, fmt.Sprintf("EventID=%d", eventID))
	}
	if filter != "" {
		if strings.HasSuffix(filter, "h") {
			var hours int
			if _, err := fmt.Sscanf(filter, "%dh", &hours); err == nil && hours > 0 {
				ms := hours * 3600 * 1000
				parts = append(parts, fmt.Sprintf("TimeCreated[timediff(@SystemTime) <= %d]", ms))
			}
		}
	}

	if len(parts) == 0 {
		return "*"
	}
	return fmt.Sprintf("*[System[%s]]", strings.Join(parts, " and "))
}

// formatEvtLogSize formats byte counts for event log display
func formatEvtLogSize(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}

// --- Scheduled Task helpers (from schtask.go) ---

// Task trigger type constants
const (
	TASK_TRIGGER_LOGON  = 9
	TASK_TRIGGER_BOOT   = 8
	TASK_TRIGGER_DAILY  = 2
	TASK_TRIGGER_WEEKLY = 3
	TASK_TRIGGER_IDLE   = 6
	TASK_TRIGGER_TIME   = 1
)

// triggerTypeFromString maps trigger name to Task Scheduler 2.0 trigger type constant
func triggerTypeFromString(trigger string) int {
	switch strings.ToUpper(trigger) {
	case "ONLOGON":
		return TASK_TRIGGER_LOGON
	case "ONSTART":
		return TASK_TRIGGER_BOOT
	case "DAILY":
		return TASK_TRIGGER_DAILY
	case "WEEKLY":
		return TASK_TRIGGER_WEEKLY
	case "ONIDLE":
		return TASK_TRIGGER_IDLE
	case "ONCE":
		return TASK_TRIGGER_TIME
	default:
		return TASK_TRIGGER_LOGON
	}
}

// escapeXML escapes special characters for XML content
func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// buildTriggerXML generates the trigger section of Task Scheduler XML
func buildTriggerXML(trigger, startTime string) string {
	switch strings.ToUpper(trigger) {
	case "ONLOGON":
		return "    <LogonTrigger>\n      <Enabled>true</Enabled>\n    </LogonTrigger>"
	case "ONSTART":
		return "    <BootTrigger>\n      <Enabled>true</Enabled>\n    </BootTrigger>"
	case "ONIDLE":
		return "    <IdleTrigger>\n      <Enabled>true</Enabled>\n    </IdleTrigger>"
	case "DAILY":
		boundary := "2026-01-01T09:00:00"
		if startTime != "" {
			boundary = fmt.Sprintf("2026-01-01T%s:00", startTime)
		}
		return fmt.Sprintf("    <CalendarTrigger>\n      <StartBoundary>%s</StartBoundary>\n      <Enabled>true</Enabled>\n      <ScheduleByDay>\n        <DaysInterval>1</DaysInterval>\n      </ScheduleByDay>\n    </CalendarTrigger>", boundary)
	case "WEEKLY":
		boundary := "2026-01-01T09:00:00"
		if startTime != "" {
			boundary = fmt.Sprintf("2026-01-01T%s:00", startTime)
		}
		return fmt.Sprintf("    <CalendarTrigger>\n      <StartBoundary>%s</StartBoundary>\n      <Enabled>true</Enabled>\n      <ScheduleByWeek>\n        <WeeksInterval>1</WeeksInterval>\n        <DaysOfWeek><Monday /></DaysOfWeek>\n      </ScheduleByWeek>\n    </CalendarTrigger>", boundary)
	case "ONCE":
		boundary := "2026-12-31T23:59:00"
		if startTime != "" {
			boundary = fmt.Sprintf("2026-01-01T%s:00", startTime)
		}
		return fmt.Sprintf("    <TimeTrigger>\n      <StartBoundary>%s</StartBoundary>\n      <Enabled>true</Enabled>\n    </TimeTrigger>", boundary)
	default:
		return "    <LogonTrigger>\n      <Enabled>true</Enabled>\n    </LogonTrigger>"
	}
}

// --- Firewall helpers (from firewall.go) ---

// Firewall protocol, direction, and action constants
const (
	fwIPProtocolTCP = 6
	fwIPProtocolUDP = 17
	fwIPProtocolAny = 256

	fwRuleDirectionIn  = 1
	fwRuleDirectionOut = 2

	fwActionBlock = 0
	fwActionAllow = 1
)

// fwDirectionToString converts a firewall rule direction to display string
func fwDirectionToString(dir int) string {
	switch dir {
	case fwRuleDirectionIn:
		return "In"
	case fwRuleDirectionOut:
		return "Out"
	default:
		return fmt.Sprintf("%d", dir)
	}
}

// fwActionIntToString converts a firewall action code to display string
func fwActionIntToString(action int) string {
	switch action {
	case fwActionBlock:
		return "Block"
	case fwActionAllow:
		return "Allow"
	default:
		return fmt.Sprintf("%d", action)
	}
}

// fwProtocolToString converts a protocol number to display string
func fwProtocolToString(proto int) string {
	switch proto {
	case fwIPProtocolTCP:
		return "TCP"
	case fwIPProtocolUDP:
		return "UDP"
	case fwIPProtocolAny:
		return "Any"
	case 1:
		return "ICMPv4"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

// --- BOF Argument Packing helpers (from beacon_api.go) ---

// bofPackArgs packs BOF arguments in Cobalt Strike format.
// Each arg is a type-prefixed string: b=binary(hex), i=int32, s=short, z=ansi, Z=wide.
// Returns the packed bytes with a 4-byte total size prefix.
func bofPackArgs(data []string) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var buff []byte
	for _, arg := range data {
		if len(arg) < 1 {
			return nil, fmt.Errorf("empty argument")
		}
		switch arg[0] {
		case 'b':
			packed, err := bofPackBinary(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("binary packing error: %v", err)
			}
			buff = append(buff, packed...)
		case 'i':
			packed, err := bofPackInt(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("int packing error: %v", err)
			}
			buff = append(buff, packed...)
		case 's':
			packed, err := bofPackShort(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("short packing error: %v", err)
			}
			buff = append(buff, packed...)
		case 'z':
			packed := bofPackString(arg[1:])
			buff = append(buff, packed...)
		case 'Z':
			packed := bofPackWideString(arg[1:])
			buff = append(buff, packed...)
		default:
			return nil, fmt.Errorf("unknown type prefix '%c'", arg[0])
		}
	}

	// Prefix with total size
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(len(buff)))
	result = append(result, buff...)
	return result, nil
}

// bofPackBinary hex-decodes data and wraps with 4-byte length prefix
func bofPackBinary(data string) ([]byte, error) {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(decoded)))
	buff = append(buff, decoded...)
	return buff, nil
}

// bofPackInt converts decimal string to 4-byte little-endian integer
func bofPackInt(s string) ([]byte, error) {
	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(val))
	return buff, nil
}

// bofPackShort converts decimal string to 2-byte little-endian integer
func bofPackShort(s string) ([]byte, error) {
	val, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, uint16(val))
	return buff, nil
}

// bofPackString wraps ANSI string with null terminator and 4-byte length prefix
func bofPackString(s string) []byte {
	data := append([]byte(s), 0)
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(data)))
	buff = append(buff, data...)
	return buff
}

// bofPackWideString encodes UTF-16LE string with null terminator and 4-byte length prefix
func bofPackWideString(s string) []byte {
	runes := []rune(s)
	data := make([]byte, 0, (len(runes)+1)*2)
	for _, r := range runes {
		data = append(data, byte(r), byte(r>>8))
	}
	data = append(data, 0, 0)

	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(data)))
	buff = append(buff, data...)
	return buff
}

// --- Thread Scan helpers (from ts.go) ---

// tsWaitReasonString converts a KWAIT_REASON enum value to human-readable string
func tsWaitReasonString(reason uint32) string {
	switch reason {
	case 0:
		return "Executive"
	case 1:
		return "FreePage"
	case 2:
		return "PageIn"
	case 3:
		return "PoolAllocation"
	case 4:
		return "DelayExecution"
	case 5:
		return "Suspended"
	case 6:
		return "UserRequest"
	case 7:
		return "WrExecutive"
	case 8:
		return "WrFreePage"
	case 9:
		return "WrPageIn"
	case 10:
		return "WrPoolAllocation"
	case 11:
		return "WrDelayExecution"
	case 12:
		return "WrSuspended"
	case 13:
		return "WrUserRequest"
	case 14:
		return "WrEventPair"
	case 15:
		return "WrQueue"
	case 16:
		return "WrLpcReceive"
	case 17:
		return "WrLpcReply"
	case 18:
		return "WrVirtualMemory"
	case 19:
		return "WrPageOut"
	case 20:
		return "WrRendezvous"
	case 21:
		return "WrKeyedEvent"
	case 22:
		return "WrTerminated"
	case 23:
		return "WrProcessInSwap"
	case 24:
		return "WrCpuRateControl"
	case 25:
		return "WrCalloutStack"
	case 26:
		return "WrKernel"
	case 27:
		return "WrResource"
	case 28:
		return "WrPushLock"
	case 29:
		return "WrMutex"
	case 30:
		return "WrQuantumEnd"
	case 31:
		return "WrDispatchInt"
	case 32:
		return "WrPreempted"
	case 33:
		return "WrYieldExecution"
	case 34:
		return "WrFastMutex"
	case 35:
		return "WrGuardedMutex"
	case 36:
		return "WrRundown"
	case 37:
		return "WrAlertByThreadId"
	case 38:
		return "WrDeferredPreempt"
	default:
		return fmt.Sprintf("Unknown(%d)", reason)
	}
}

// tsTruncateOwner truncates a process owner string to maxLen, adding "..." if truncated
func tsTruncateOwner(owner string, maxLen int) string {
	if len(owner) <= maxLen {
		return owner
	}
	return owner[:maxLen-3] + "..."
}
