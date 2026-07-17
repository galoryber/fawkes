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

var (
	fltlib              = windows.NewLazySystemDLL("fltlib.dll")
	procFilterFindFirst = fltlib.NewProc("FilterFindFirst")
	procFilterFindNext  = fltlib.NewProc("FilterFindNext")
	procFilterFindClose = fltlib.NewProc("FilterFindClose")
)

const (
	filterFullInformation               = 0
	sHresultFromWin32ErrorNoMoreItems    = 0x80070103
	sHresultFromWin32ErrorNoMoreEntries  = 0x8007010B
	sHresultFromWin32InsufficientBuffer  = 0x8007007A
)

type minifilterInfo struct {
	Name       string `json:"name"`
	FrameID    uint32 `json:"frame_id"`
	Instances  uint32 `json:"instances"`
	EDRVendor  string `json:"edr_vendor,omitempty"`
	EDRProduct string `json:"edr_product,omitempty"`
}

var knownEDRMinifilters = map[string]struct{ vendor, product string }{
	"wdfilter":           {"Microsoft", "Defender"},
	"wd guard":           {"Microsoft", "Defender"},
	"csagent":            {"CrowdStrike", "Falcon"},
	"csdevicecontrol":    {"CrowdStrike", "Falcon"},
	"csboot":             {"CrowdStrike", "Falcon"},
	"sentinelmonitor":    {"SentinelOne", "SentinelOne"},
	"cbfilter":           {"VMware", "Carbon Black"},
	"cbdefense":          {"VMware", "Carbon Black"},
	"carbonblackk":       {"VMware", "Carbon Black"},
	"savonaccess":        {"Sophos", "Sophos AV"},
	"sophosed":           {"Sophos", "Sophos Endpoint"},
	"eamonm":             {"ESET", "ESET Endpoint"},
	"ekbdflt":            {"ESET", "ESET Endpoint"},
	"klif":               {"Kaspersky", "Kaspersky Endpoint"},
	"klflt":              {"Kaspersky", "Kaspersky Endpoint"},
	"klam":               {"Kaspersky", "Kaspersky Endpoint"},
	"tmfsdrv2":           {"Trend Micro", "Trend Micro"},
	"fileflt":            {"Trend Micro", "Trend Micro"},
	"tmactmon":           {"Trend Micro", "Trend Micro"},
	"srtsp":              {"Broadcom", "Symantec"},
	"symefasi":           {"Broadcom", "Symantec"},
	"symevent":           {"Broadcom", "Symantec"},
	"cyvrfsfd":           {"Palo Alto", "Cortex XDR"},
	"cytflt":             {"Palo Alto", "Cortex XDR"},
	"mfehidk":            {"Trellix", "McAfee/Trellix"},
	"mfeaack":            {"Trellix", "McAfee/Trellix"},
	"cyoptics":           {"Cybereason", "Cybereason EDR"},
	"cyprotectdrv":       {"Cybereason", "Cybereason EDR"},
	"cylancedrv":         {"BlackBerry", "Cylance"},
	"bdflt":              {"Bitdefender", "Bitdefender"},
	"bdsandbox":          {"Bitdefender", "Bitdefender"},
	"elasticendpoint":    {"Elastic", "Elastic Agent"},
	"sysmondrv":          {"Microsoft", "Sysmon"},
	"fltmgr":             {"Microsoft", "Filter Manager"},
}

func securityInfoMinifilterEnum() structs.CommandResult {
	if err := fltlib.Load(); err != nil {
		return errorf("filter manager library not available: %v", err)
	}

	var filters []minifilterInfo
	bufSize := uint32(4096)
	buf := make([]byte, bufSize)
	var bytesReturned uint32
	var findHandle uintptr

	hr, _, _ := procFilterFindFirst.Call(
		filterFullInformation,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bufSize),
		uintptr(unsafe.Pointer(&bytesReturned)),
		uintptr(unsafe.Pointer(&findHandle)),
	)

	if hr != 0 {
		if uint32(hr) == sHresultFromWin32ErrorNoMoreItems {
			return successResult("No minifilter drivers loaded.")
		}
		if uint32(hr) == 0x80070005 {
			return errorf("FilterFindFirst failed: access denied — requires elevated (high integrity) privileges")
		}
		return errorf("FilterFindFirst failed: HRESULT 0x%08X", uint32(hr))
	}

	fi := parseFilterFullInfo(buf[:bytesReturned])
	if fi != nil {
		classifyMinifilter(fi)
		filters = append(filters, *fi)
	}

	for {
		hr, _, _ = procFilterFindNext.Call(
			findHandle,
			filterFullInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&bytesReturned)),
		)
		if hr != 0 {
			break
		}
		fi = parseFilterFullInfo(buf[:bytesReturned])
		if fi != nil {
			classifyMinifilter(fi)
			filters = append(filters, *fi)
		}
	}

	procFilterFindClose.Call(findHandle)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Minifilter Drivers — %d loaded\n\n", len(filters)))
	sb.WriteString(fmt.Sprintf("%-30s %-6s %-10s %s\n", "FILTER NAME", "FRAME", "INSTANCES", "SECURITY RELEVANCE"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	edrCount := 0
	for _, f := range filters {
		relevance := ""
		if f.EDRVendor != "" {
			relevance = fmt.Sprintf("[EDR] %s — %s", f.EDRVendor, f.EDRProduct)
			edrCount++
		}
		sb.WriteString(fmt.Sprintf("%-30s %-6d %-10d %s\n",
			truncStr(f.Name, 30), f.FrameID, f.Instances, relevance))
	}

	if edrCount > 0 {
		sb.WriteString(fmt.Sprintf("\n[!] %d security-related minifilter(s) detected\n", edrCount))
	} else {
		sb.WriteString("\n[+] No known EDR minifilters detected\n")
	}

	return successResult(sb.String())
}

func parseFilterFullInfo(buf []byte) *minifilterInfo {
	if len(buf) < 14 {
		return nil
	}

	frameID := binary.LittleEndian.Uint32(buf[4:8])
	instances := binary.LittleEndian.Uint32(buf[8:12])
	nameLen := binary.LittleEndian.Uint16(buf[12:14])

	name := ""
	if nameLen > 0 && int(14+nameLen) <= len(buf) {
		nameBytes := buf[14 : 14+nameLen]
		u16s := make([]uint16, nameLen/2)
		for i := range u16s {
			u16s[i] = binary.LittleEndian.Uint16(nameBytes[i*2 : i*2+2])
		}
		name = windows.UTF16ToString(u16s)
	}

	return &minifilterInfo{
		Name:      name,
		FrameID:   frameID,
		Instances: instances,
	}
}

func classifyMinifilter(fi *minifilterInfo) {
	nameLower := strings.ToLower(fi.Name)
	if info, ok := knownEDRMinifilters[nameLower]; ok {
		fi.EDRVendor = info.vendor
		fi.EDRProduct = info.product
	}
}
