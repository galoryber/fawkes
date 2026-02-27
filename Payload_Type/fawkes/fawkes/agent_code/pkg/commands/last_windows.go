//go:build windows

package commands

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Reuses procEvtQuery, procEvtNext, procEvtRender, procEvtClose,
// evtQueryChannelPath, evtRenderEventXml, extractXMLField, extractXMLAttr
// from eventlog.go (same package)

func lastPlatform(args lastArgs) string {
	var sb strings.Builder
	sb.WriteString("=== Windows Login History ===\n\n")
	sb.WriteString(lastHeader())

	// Query Security event log for logon events (Event ID 4624)
	query := `*[System[(EventID=4624)]]`
	channelPath, _ := syscall.UTF16PtrFromString("Security")
	queryStr, _ := syscall.UTF16PtrFromString(query)

	handle, _, err := procEvtQuery.Call(
		0, // local
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(queryStr)),
		evtQueryChannelPath|evtQueryReverseDirection,
	)
	if handle == 0 {
		sb.WriteString(fmt.Sprintf("[!] Cannot read Security log (requires admin): %v\n", err))
		sb.WriteString("[*] Logon session enumeration requires Security event log access\n")
		return sb.String()
	}
	defer procEvtClose.Call(handle)

	count := 0
	events := make([]uintptr, 1)
	var returned uint32
	buf := make([]uint16, 8192)

	for count < args.Count {
		r, _, _ := procEvtNext.Call(
			handle,
			1,
			uintptr(unsafe.Pointer(&events[0])),
			5000, // timeout ms
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

		// Parse basic info from XML
		user := extractXMLField(xml, "TargetUserName")
		domain := extractXMLField(xml, "TargetDomainName")
		logonType := extractXMLField(xml, "LogonType")
		source := extractXMLField(xml, "IpAddress")
		timeStr := extractXMLAttr(xml, "TimeCreated", "SystemTime")

		// Filter interactive/remote logons (2=Interactive, 3=Network, 7=Unlock, 10=RemoteInteractive)
		if logonType != "2" && logonType != "3" && logonType != "10" && logonType != "7" {
			continue
		}

		// Skip system/service accounts
		if user == "-" || user == "" || strings.HasSuffix(user, "$") {
			continue
		}

		if args.User != "" && !strings.EqualFold(user, args.User) {
			continue
		}

		logonTypeStr := logonTypeName(logonType)
		fullUser := user
		if domain != "" && domain != "-" {
			fullUser = domain + "\\" + user
		}

		sb.WriteString(formatLastEntry(fullUser, logonTypeStr, source, timeStr, ""))
		count++
	}

	sb.WriteString(fmt.Sprintf("\n%d logon events shown", count))
	return sb.String()
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
