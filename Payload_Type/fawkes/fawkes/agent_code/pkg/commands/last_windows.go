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
