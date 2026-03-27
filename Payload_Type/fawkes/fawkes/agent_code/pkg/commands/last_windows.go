//go:build windows

package commands

import (
	"strings"
	"syscall"
	"unsafe"
)

// Reuses procEvtQuery, procEvtNext, procEvtRender, procEvtClose,
// evtQueryChannelPath, evtRenderEventXml, extractXMLField, extractXMLAttr
// from eventlog.go (same package)

func lastPlatform(args lastArgs) []lastLoginEntry {
	query := `*[System[(EventID=4624)]]`
	channelPath, _ := syscall.UTF16PtrFromString("Security")
	queryStr, _ := syscall.UTF16PtrFromString(query)

	handle, _, _ := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(queryStr)),
		evtQueryChannelPath|evtQueryReverseDirection,
	)
	if handle == 0 {
		return nil
	}
	defer procEvtClose.Call(handle)

	var entries []lastLoginEntry
	events := make([]uintptr, 1)
	var returned uint32
	buf := make([]uint16, 8192)

	for len(entries) < args.Count {
		r, _, _ := procEvtNext.Call(
			handle,
			1,
			uintptr(unsafe.Pointer(&events[0])),
			5000,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if r == 0 || returned == 0 {
			break
		}

		var bufUsed, propCount uint32
		procEvtRender.Call(
			0,
			events[0],
			evtRenderEventXml,
			uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufUsed)),
			uintptr(unsafe.Pointer(&propCount)),
		)
		procEvtClose.Call(events[0])

		xml := syscall.UTF16ToString(buf[:bufUsed/2])

		user := extractXMLField(xml, "TargetUserName")
		domain := extractXMLField(xml, "TargetDomainName")
		logonType := extractXMLField(xml, "LogonType")
		source := extractXMLField(xml, "IpAddress")
		timeStr := extractXMLAttr(xml, "TimeCreated", "SystemTime")

		if logonType != "2" && logonType != "3" && logonType != "10" && logonType != "7" {
			continue
		}

		if user == "-" || user == "" || strings.HasSuffix(user, "$") {
			continue
		}

		if args.User != "" && !strings.EqualFold(user, args.User) {
			continue
		}

		fullUser := user
		if domain != "" && domain != "-" {
			fullUser = domain + "\\" + user
		}

		from := source
		if from == "" {
			from = "-"
		}

		entries = append(entries, lastLoginEntry{
			User:      fullUser,
			TTY:       logonTypeName(logonType),
			From:      from,
			LoginTime: timeStr,
		})
	}

	return entries
}

// lastFailedPlatform queries Security event log for failed logon events (4625).
func lastFailedPlatform(args lastArgs) []lastLoginEntry {
	query := `*[System[(EventID=4625)]]`
	channelPath, _ := syscall.UTF16PtrFromString("Security")
	queryStr, _ := syscall.UTF16PtrFromString(query)

	handle, _, _ := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(queryStr)),
		evtQueryChannelPath|evtQueryReverseDirection,
	)
	if handle == 0 {
		return nil
	}
	defer procEvtClose.Call(handle)

	var entries []lastLoginEntry
	events := make([]uintptr, 1)
	var returned uint32
	buf := make([]uint16, 8192)

	for len(entries) < args.Count {
		r, _, _ := procEvtNext.Call(
			handle,
			1,
			uintptr(unsafe.Pointer(&events[0])),
			5000,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if r == 0 || returned == 0 {
			break
		}

		var bufUsed, propCount uint32
		procEvtRender.Call(
			0,
			events[0],
			evtRenderEventXml,
			uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufUsed)),
			uintptr(unsafe.Pointer(&propCount)),
		)
		procEvtClose.Call(events[0])

		xml := syscall.UTF16ToString(buf[:bufUsed/2])

		user := extractXMLField(xml, "TargetUserName")
		domain := extractXMLField(xml, "TargetDomainName")
		source := extractXMLField(xml, "IpAddress")
		timeStr := extractXMLAttr(xml, "TimeCreated", "SystemTime")

		if user == "-" || user == "" || strings.HasSuffix(user, "$") {
			continue
		}
		if args.User != "" && !strings.EqualFold(user, args.User) {
			continue
		}

		fullUser := user
		if domain != "" && domain != "-" {
			fullUser = domain + "\\" + user
		}
		from := source
		if from == "" {
			from = "-"
		}

		entries = append(entries, lastLoginEntry{
			User:      fullUser,
			TTY:       "-",
			From:      from,
			LoginTime: timeStr,
			Duration:  "FAILED",
		})
	}

	return entries
}

// lastRebootPlatform queries System event log for boot/shutdown events.
// Event IDs: 6005 (Event Log started = boot), 6006 (Event Log stopped = clean shutdown),
// 6008 (unexpected shutdown), 1074 (user-initiated restart/shutdown).
func lastRebootPlatform(args lastArgs) []lastLoginEntry {
	query := `*[System[(EventID=6005 or EventID=6006 or EventID=6008 or EventID=1074)]]`
	channelPath, _ := syscall.UTF16PtrFromString("System")
	queryStr, _ := syscall.UTF16PtrFromString(query)

	handle, _, _ := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(queryStr)),
		evtQueryChannelPath|evtQueryReverseDirection,
	)
	if handle == 0 {
		return nil
	}
	defer procEvtClose.Call(handle)

	var entries []lastLoginEntry
	events := make([]uintptr, 1)
	var returned uint32
	buf := make([]uint16, 8192)

	for len(entries) < args.Count {
		r, _, _ := procEvtNext.Call(
			handle,
			1,
			uintptr(unsafe.Pointer(&events[0])),
			5000,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if r == 0 || returned == 0 {
			break
		}

		var bufUsed, propCount uint32
		procEvtRender.Call(
			0,
			events[0],
			evtRenderEventXml,
			uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufUsed)),
			uintptr(unsafe.Pointer(&propCount)),
		)
		procEvtClose.Call(events[0])

		xml := syscall.UTF16ToString(buf[:bufUsed/2])

		eventID := extractXMLField(xml, "EventID")
		timeStr := extractXMLAttr(xml, "TimeCreated", "SystemTime")

		eventType := rebootEventName(eventID)
		if eventType == "" {
			continue
		}

		// For 1074 (user-initiated), extract who requested it
		user := "system"
		if eventID == "1074" {
			if u := extractXMLField(xml, "param5"); u != "" {
				user = u
			}
		}

		entries = append(entries, lastLoginEntry{
			User:      user,
			TTY:       eventType,
			From:      "-",
			LoginTime: timeStr,
		})
	}

	return entries
}

func rebootEventName(eventID string) string {
	switch eventID {
	case "6005":
		return "boot"
	case "6006":
		return "shutdown"
	case "6008":
		return "crash"
	case "1074":
		return "restart"
	default:
		return ""
	}
}

func logonTypeName(lt string) string {
	switch lt {
	case "2":
		return "Interactive"
	case "3":
		return "Network"
	case "7":
		return "Unlock"
	case "10":
		return "RemoteDP"
	case "11":
		return "CachedInt"
	default:
		return "Type" + lt
	}
}
