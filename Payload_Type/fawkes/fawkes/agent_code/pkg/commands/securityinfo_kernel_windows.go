//go:build windows
// +build windows

package commands

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	ntdllKernel                    = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySystemInformationKD = ntdllKernel.NewProc("NtQuerySystemInformation")
)

const systemModuleInformation = 11

type kernelDriverInfo struct {
	Name       string `json:"name"`
	FullPath   string `json:"path"`
	ImageBase  uint64 `json:"image_base"`
	ImageSize  uint32 `json:"image_size"`
	LoadOrder  uint16 `json:"load_order"`
	EDRVendor  string `json:"edr_vendor,omitempty"`
	EDRProduct string `json:"edr_product,omitempty"`
	CallbackType string `json:"callback_type,omitempty"`
}

var knownEDRDrivers = map[string]struct {
	vendor, product, callbacks string
}{
	"wdfilter.sys":              {"Microsoft", "Defender", "minifilter,process,image"},
	"wd guard.sys":              {"Microsoft", "Defender", "process"},
	"mssecflt.sys":              {"Microsoft", "Defender", "minifilter"},
	"csagent.sys":               {"CrowdStrike", "Falcon", "minifilter,process,thread,image,registry,object"},
	"csdevicecontrol.sys":       {"CrowdStrike", "Falcon", "minifilter"},
	"csboot.sys":                {"CrowdStrike", "Falcon", "boot"},
	"sentinelmonitor.sys":       {"SentinelOne", "SentinelOne", "minifilter,process,thread,image"},
	"cbfilter.sys":              {"VMware", "Carbon Black", "minifilter"},
	"cbk7.sys":                  {"VMware", "Carbon Black", "minifilter,process"},
	"savonaccess.sys":           {"Sophos", "Sophos AV", "minifilter"},
	"sophosed.sys":              {"Sophos", "Sophos EDR", "process,thread,image,registry"},
	"eamonm.sys":                {"ESET", "ESET Endpoint", "minifilter"},
	"ekbdflt.sys":               {"ESET", "ESET Endpoint", "minifilter"},
	"ehdrv.sys":                 {"ESET", "ESET Endpoint", "process"},
	"klif.sys":                  {"Kaspersky", "Kaspersky Endpoint", "minifilter,process,registry"},
	"klflt.sys":                 {"Kaspersky", "Kaspersky Endpoint", "minifilter"},
	"klam.sys":                  {"Kaspersky", "Kaspersky Endpoint", "minifilter"},
	"tmfsdrv2.sys":              {"Trend Micro", "Trend Micro", "minifilter"},
	"fileflt.sys":               {"Trend Micro", "Trend Micro", "minifilter"},
	"tmactmon.sys":              {"Trend Micro", "Trend Micro", "process,image"},
	"srtsp.sys":                 {"Broadcom", "Symantec", "minifilter"},
	"symefasi.sys":              {"Broadcom", "Symantec", "minifilter"},
	"symevent.sys":              {"Broadcom", "Symantec", "process,thread"},
	"cyvrfsfd.sys":              {"Palo Alto", "Cortex XDR", "minifilter"},
	"cytflt.sys":                {"Palo Alto", "Cortex XDR", "minifilter"},
	"mfehidk.sys":               {"Trellix", "McAfee/Trellix", "minifilter,process,image"},
	"mfeaack.sys":               {"Trellix", "McAfee/Trellix", "minifilter"},
	"cyoptics.sys":              {"Cybereason", "Cybereason EDR", "process,thread,image"},
	"cyprotectdrv64.sys":        {"Cybereason", "Cybereason EDR", "minifilter,process"},
	"cylancedrv64.sys":          {"BlackBerry", "Cylance", "process,image"},
	"bdflt.sys":                 {"Bitdefender", "Bitdefender", "minifilter"},
	"bdsandbox.sys":             {"Bitdefender", "Bitdefender", "minifilter,process"},
	"elasticendpoint.sys":       {"Elastic", "Elastic Agent", "minifilter,process"},
	"sysmondrv.sys":             {"Microsoft", "Sysmon", "minifilter,process,thread,image,registry,network"},
	"fltmgr.sys":                {"Microsoft", "Filter Manager", "framework"},
	"ci.sys":                    {"Microsoft", "Code Integrity", "image"},
	"ksecdd.sys":                {"Microsoft", "Kernel Security", "crypto"},
	"cng.sys":                   {"Microsoft", "CNG Key Isolation", "crypto"},
	"tcpip.sys":                 {"Microsoft", "TCP/IP Stack", "network"},
	"ndis.sys":                  {"Microsoft", "NDIS", "network"},
	"wfplwfs.sys":               {"Microsoft", "Windows Filtering Platform", "network"},
	"nsiproxy.sys":              {"Microsoft", "NSI Proxy", "network"},
}

func securityInfoKernelDrivers() structs.CommandResult {
	var requiredSize uint32
	procNtQuerySystemInformationKD.Call(
		systemModuleInformation,
		0,
		0,
		uintptr(unsafe.Pointer(&requiredSize)),
	)

	if requiredSize == 0 {
		return errorResult("NtQuerySystemInformation returned 0 size — may require elevated privileges")
	}

	buf := make([]byte, requiredSize)
	r1, _, _ := procNtQuerySystemInformationKD.Call(
		systemModuleInformation,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(requiredSize),
		uintptr(unsafe.Pointer(&requiredSize)),
	)

	if r1 != 0 {
		return errorf("NtQuerySystemInformation failed: NTSTATUS 0x%08X — requires SYSTEM or SeDebugPrivilege", uint32(r1))
	}

	// RTL_PROCESS_MODULES: first 8 bytes = NumberOfModules (ULONG on x64 with padding)
	numModules := *(*uint32)(unsafe.Pointer(&buf[0]))

	// Each RTL_PROCESS_MODULE_INFORMATION is 296 bytes on x64:
	// Section(8) + MappedBase(8) + ImageBase(8) + ImageSize(4) + Flags(4) +
	// LoadOrderIndex(2) + InitOrderIndex(2) + LoadCount(2) + OffsetToFileName(2) +
	// FullPathName(256) = 296
	const moduleInfoSize = 296
	const moduleOffset = 8 // start of first module after NumberOfModules + padding

	var drivers []kernelDriverInfo
	edrCount := 0

	for i := uint32(0); i < numModules; i++ {
		offset := moduleOffset + int(i)*moduleInfoSize
		if offset+moduleInfoSize > len(buf) {
			break
		}

		entry := buf[offset : offset+moduleInfoSize]

		imageBase := *(*uint64)(unsafe.Pointer(&entry[16]))
		imageSize := *(*uint32)(unsafe.Pointer(&entry[24]))
		loadOrder := *(*uint16)(unsafe.Pointer(&entry[32]))
		offsetToFileName := *(*uint16)(unsafe.Pointer(&entry[36]))

		fullPathBytes := entry[40 : 40+256]
		fullPath := bytesToGoString(fullPathBytes)
		name := fullPath
		if int(offsetToFileName) < len(fullPath) {
			name = fullPath[offsetToFileName:]
		} else {
			name = filepath.Base(fullPath)
		}

		di := kernelDriverInfo{
			Name:      name,
			FullPath:  fullPath,
			ImageBase: imageBase,
			ImageSize: imageSize,
			LoadOrder: loadOrder,
		}

		nameLower := strings.ToLower(name)
		if info, ok := knownEDRDrivers[nameLower]; ok {
			di.EDRVendor = info.vendor
			di.EDRProduct = info.product
			di.CallbackType = info.callbacks
			edrCount++
		}

		drivers = append(drivers, di)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Loaded Kernel Drivers — %d total\n\n", len(drivers)))

	if edrCount > 0 {
		sb.WriteString(fmt.Sprintf("Security-Relevant Drivers (%d found):\n", edrCount))
		sb.WriteString(fmt.Sprintf("%-30s %-25s %-20s %s\n", "DRIVER", "VENDOR/PRODUCT", "CALLBACKS", "BASE"))
		sb.WriteString(strings.Repeat("-", 100) + "\n")

		for _, d := range drivers {
			if d.EDRVendor == "" {
				continue
			}
			vendorProduct := d.EDRVendor
			if d.EDRProduct != "" {
				vendorProduct = fmt.Sprintf("%s/%s", d.EDRVendor, d.EDRProduct)
			}
			sb.WriteString(fmt.Sprintf("%-30s %-25s %-20s 0x%X\n",
				truncStr(d.Name, 30),
				truncStr(vendorProduct, 25),
				truncStr(d.CallbackType, 20),
				d.ImageBase))
		}
	} else {
		sb.WriteString("[+] No known EDR kernel drivers detected\n")
	}

	sb.WriteString(fmt.Sprintf("\n%d total drivers loaded (%d security-relevant)\n", len(drivers), edrCount))

	return successResult(sb.String())
}

func bytesToGoString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
