package commands

import (
	"fmt"
	"strings"
)

// --- Event Log helpers (from eventlog.go) ---

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
