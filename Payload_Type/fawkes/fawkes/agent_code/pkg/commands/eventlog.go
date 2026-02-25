//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	wevtapi                = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtOpenChannelEnum = wevtapi.NewProc("EvtOpenChannelEnum")
	procEvtNextChannelPath = wevtapi.NewProc("EvtNextChannelPath")
	procEvtQuery           = wevtapi.NewProc("EvtQuery")
	procEvtNext            = wevtapi.NewProc("EvtNext")
	procEvtRender          = wevtapi.NewProc("EvtRender")
	procEvtClose           = wevtapi.NewProc("EvtClose")
	procEvtOpenLog         = wevtapi.NewProc("EvtOpenLog")
	procEvtGetLogInfo      = wevtapi.NewProc("EvtGetLogInfo")
	procEvtClearLog        = wevtapi.NewProc("EvtClearLog")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXml        = 1
	evtOpenChannelPath       = 1
	evtLogNumberOfLogRecords = 5
	evtLogFileSize           = 3
	evtLogLastWriteTime      = 2
	errorNoMoreItems         = 259
	errorInsufficientBuffer  = 122
)

// EventLogCommand manages Windows Event Logs
type EventLogCommand struct{}

func (c *EventLogCommand) Name() string {
	return "eventlog"
}

func (c *EventLogCommand) Description() string {
	return "Manage Windows Event Logs — list channels, query events, clear logs, get info"
}

type eventlogArgs struct {
	Action  string `json:"action"`
	Channel string `json:"channel"`
	Filter  string `json:"filter"`
	EventID int    `json:"event_id"`
	Count   int    `json:"count"`
}

func (c *EventLogCommand) Execute(task structs.Task) structs.CommandResult {
	var args eventlogArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch args.Action {
	case "list":
		return evtListChannels(args.Filter)
	case "query":
		return evtQueryEvents(args.Channel, args.Filter, args.EventID, args.Count)
	case "clear":
		return evtClear(args.Channel)
	case "info":
		return evtInfo(args.Channel)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use list, query, clear, info)", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func evtListChannels(filter string) structs.CommandResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	enumHandle, _, err := procEvtOpenChannelEnum.Call(0, 0)
	if enumHandle == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("EvtOpenChannelEnum failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procEvtClose.Call(enumHandle)

	var channels []string
	buf := make([]uint16, 512)

	for {
		var used uint32
		ret, _, callErr := procEvtNextChannelPath.Call(
			enumHandle,
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)),
		)
		if ret == 0 {
			errno := uintptr(callErr.(windows.Errno))
			if errno == errorNoMoreItems {
				break
			}
			if errno == errorInsufficientBuffer {
				buf = make([]uint16, used)
				continue
			}
			break
		}
		name := windows.UTF16ToString(buf[:used])
		if filter == "" || strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			channels = append(channels, name)
		}
	}

	if len(channels) == 0 {
		msg := "No event log channels found"
		if filter != "" {
			msg += fmt.Sprintf(" matching '%s'", filter)
		}
		return structs.CommandResult{
			Output:    msg,
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Event Log Channels (%d", len(channels)))
	if filter != "" {
		sb.WriteString(fmt.Sprintf(", filter: '%s'", filter))
	}
	sb.WriteString("):\n\n")
	for _, ch := range channels {
		sb.WriteString(fmt.Sprintf("  %s\n", ch))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func evtQueryEvents(channel, filter string, eventID, maxCount int) structs.CommandResult {
	if channel == "" {
		return structs.CommandResult{
			Output:    "Channel is required for query action (e.g., Security, System, Application)",
			Status:    "error",
			Completed: true,
		}
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Build XPath query
	xpath := buildEventXPath(filter, eventID)

	channelPtr, _ := windows.UTF16PtrFromString(channel)
	var queryPtr uintptr
	if xpath != "*" {
		xpathUTF16, _ := windows.UTF16PtrFromString(xpath)
		queryPtr = uintptr(unsafe.Pointer(xpathUTF16))
	}

	queryHandle, _, err := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		queryPtr,
		evtQueryChannelPath|evtQueryReverseDirection,
	)
	if queryHandle == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("EvtQuery failed on '%s': %v\nXPath: %s", channel, err, xpath),
			Status:    "error",
			Completed: true,
		}
	}
	defer procEvtClose.Call(queryHandle)

	if maxCount <= 0 {
		maxCount = 50
	}

	// Fetch events
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Events from '%s' (max %d, newest first):\n", channel, maxCount))
	if xpath != "*" {
		sb.WriteString(fmt.Sprintf("XPath: %s\n", xpath))
	}
	sb.WriteString("\n")

	total := 0
	const batchSize = 10
	events := make([]uintptr, batchSize)

	for total < maxCount {
		var returned uint32
		ret, _, fetchErr := procEvtNext.Call(
			queryHandle,
			uintptr(batchSize),
			uintptr(unsafe.Pointer(&events[0])),
			5000,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 {
			errno := uintptr(fetchErr.(windows.Errno))
			if errno == errorNoMoreItems {
				break
			}
			sb.WriteString(fmt.Sprintf("EvtNext error: %v\n", fetchErr))
			break
		}

		for i := uint32(0); i < returned; i++ {
			if total < maxCount {
				xml, renderErr := renderEventXML(events[i])
				procEvtClose.Call(events[i])
				if renderErr != nil {
					continue
				}
				summary := summarizeEventXML(xml)
				sb.WriteString(fmt.Sprintf("[%d] %s\n", total+1, summary))
				total++
			} else {
				procEvtClose.Call(events[i])
			}
		}
	}

	if total == 0 {
		sb.WriteString("No events found matching the query.\n")
	} else {
		sb.WriteString(fmt.Sprintf("\nTotal: %d events returned\n", total))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func evtClear(channel string) structs.CommandResult {
	if channel == "" {
		return structs.CommandResult{
			Output:    "Channel is required for clear action (e.g., Security, System, Application)",
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("EvtClearLog failed for '%s': %v\nEnsure you have sufficient privileges (Administrator/SYSTEM for Security log).", channel, err),
			Status:    "error",
			Completed: true,
		}
	}

	msg := fmt.Sprintf("Successfully cleared '%s' event log", channel)
	if countBefore > 0 {
		msg += fmt.Sprintf(" (%d events removed)", countBefore)
	}
	msg += "\nNote: Event ID 1102 (log cleared) is automatically recorded in Security."

	return structs.CommandResult{
		Output:    msg,
		Status:    "success",
		Completed: true,
	}
}

func evtInfo(channel string) structs.CommandResult {
	if channel == "" {
		return structs.CommandResult{
			Output:    "Channel is required for info action (e.g., Security, System, Application)",
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("EvtOpenLog failed for '%s': %v", channel, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procEvtClose.Call(logHandle)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Event Log Info: %s\n\n", channel))

	// Record count
	count := evtGetLogProperty(logHandle, evtLogNumberOfLogRecords)
	sb.WriteString(fmt.Sprintf("  Records:     %d\n", count))

	// File size
	size := evtGetLogProperty(logHandle, evtLogFileSize)
	sb.WriteString(fmt.Sprintf("  File Size:   %s\n", formatEvtLogSize(size)))

	// Last write time
	lastWrite := evtGetLogProperty(logHandle, evtLogLastWriteTime)
	if lastWrite > 0 {
		sb.WriteString(fmt.Sprintf("  Last Write:  %s\n", windowsFileTimeToString(lastWrite)))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
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
		return "", fmt.Errorf("EvtRender failed: %v", err)
	}

	// Convert UTF-16LE to string
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), bufUsed/2)
	return windows.UTF16ToString(u16), nil
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

	// Truncate time to readable format
	if len(timeCreated) > 19 {
		timeCreated = timeCreated[:19]
	}

	return fmt.Sprintf("%s | EventID: %s | %s | %s", timeCreated, eventID, levelName, provider)
}

// extractXMLField extracts a simple element value like <EventID>4624</EventID>
func extractXMLField(xml, field string) string {
	start := fmt.Sprintf("<%s>", field)
	// Also handle <EventID Qualifiers='0'> style
	startAlt := fmt.Sprintf("<%s ", field)
	end := fmt.Sprintf("</%s>", field)

	idx := strings.Index(xml, start)
	if idx == -1 {
		idx = strings.Index(xml, startAlt)
		if idx == -1 {
			return ""
		}
		// Find the > after attributes
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

func buildEventXPath(filter string, eventID int) string {
	// If filter is provided as raw XPath, use it directly
	if filter != "" && (strings.HasPrefix(filter, "*[") || strings.HasPrefix(filter, "<QueryList")) {
		return filter
	}

	var parts []string
	if eventID > 0 {
		parts = append(parts, fmt.Sprintf("EventID=%d", eventID))
	}
	if filter != "" {
		// Treat filter as a keyword — check common patterns
		// If it looks like a time filter (e.g., "24h", "1h")
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

func windowsFileTimeToString(ft uint64) string {
	if ft == 0 {
		return "unknown"
	}
	// FILETIME is 100-nanosecond intervals since 1601-01-01
	// Epoch difference: 1601 to 1970 = 11644473600 seconds = 116444736000000000 100-ns intervals
	const epochDiff100ns = 116444736000000000
	if ft < epochDiff100ns {
		return "unknown"
	}
	unixSec := int64((ft - epochDiff100ns) / 10000000)
	days := unixSec / 86400
	rem := unixSec % 86400
	hours := rem / 3600
	mins := (rem % 3600) / 60
	secs := rem % 60
	year, month, day := daysToDate(days)
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d UTC", year, month, day, hours, mins, secs)
}

func daysToDate(days int64) (int64, int64, int64) {
	// Algorithm from https://howardhinnant.github.io/date_algorithms.html
	z := days + 719468
	era := z / 146097
	if z < 0 {
		era = (z - 146096) / 146097
	}
	doe := z - era*146097
	yoe := (doe - doe/1460 + doe/36524 - doe/146096) / 365
	y := yoe + era*400
	doy := doe - (365*yoe + yoe/4 - yoe/100)
	mp := (5*doy + 2) / 153
	d := doy - (153*mp+2)/5 + 1
	m := mp + 3
	if mp >= 10 {
		m = mp - 9
	}
	if m <= 2 {
		y++
	}
	return y, m, d
}

// enableSecurityPrivilege enables SeSecurityPrivilege on the process token
func enableSecurityPrivilege() error {
	var token windows.Token
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	err = windows.OpenProcessToken(processHandle, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeSecurityPrivilege"), &luid)
	if err != nil {
		return err
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
		return err
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeSecurityPrivilege"), &luid)
	if err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}
