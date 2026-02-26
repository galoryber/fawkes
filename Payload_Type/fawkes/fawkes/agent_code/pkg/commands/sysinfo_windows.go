//go:build windows

package commands

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32SI       = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemSI  = kernel32SI.NewProc("GlobalMemoryStatusEx")
	procGetTickCount = kernel32SI.NewProc("GetTickCount64")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func collectPlatformSysinfo(sb *strings.Builder) {
	sb.WriteString("--- Windows Details ---\n")

	// OS version from registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()

		productName, _, _ := key.GetStringValue("ProductName")
		displayVersion, _, _ := key.GetStringValue("DisplayVersion")
		buildNum, _, _ := key.GetStringValue("CurrentBuildNumber")
		ubr, _, _ := key.GetIntegerValue("UBR")

		if productName != "" {
			sb.WriteString(fmt.Sprintf("Product:       %s\n", productName))
		}
		if displayVersion != "" {
			sb.WriteString(fmt.Sprintf("Version:       %s\n", displayVersion))
		}
		if buildNum != "" {
			sb.WriteString(fmt.Sprintf("Build:         %s.%d\n", buildNum, ubr))
		}
	}

	// Computer name and domain
	var size uint32 = 256
	buf := make([]uint16, size)
	if windows.GetComputerNameEx(windows.ComputerNameDnsFullyQualified, &buf[0], &size) == nil {
		sb.WriteString(fmt.Sprintf("FQDN:          %s\n", windows.UTF16ToString(buf[:size])))
	}

	size = 256
	buf = make([]uint16, size)
	if windows.GetComputerNameEx(windows.ComputerNameDnsDomain, &buf[0], &size) == nil {
		domain := windows.UTF16ToString(buf[:size])
		if domain != "" {
			sb.WriteString(fmt.Sprintf("Domain:        %s\n", domain))
		} else {
			sb.WriteString("Domain:        (not domain-joined)\n")
		}
	}

	// Memory
	var mem memoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	ret, _, _ := procGlobalMemSI.Call(uintptr(unsafe.Pointer(&mem)))
	if ret != 0 {
		sb.WriteString(fmt.Sprintf("Total Memory:  %s\n", formatFileSize(int64(mem.TotalPhys))))
		sb.WriteString(fmt.Sprintf("Avail Memory:  %s (%d%% used)\n",
			formatFileSize(int64(mem.AvailPhys)), mem.MemoryLoad))
	}

	// Uptime via GetTickCount64
	var ticks uint64
	ret, _, _ = procGetTickCount.Call(uintptr(unsafe.Pointer(&ticks)))
	if ret != 0 {
		// GetTickCount64 returns value in rax, not via pointer
		ticks = uint64(ret)
	}
	if ticks > 0 {
		uptime := time.Duration(ticks) * time.Millisecond
		days := int(uptime.Hours()) / 24
		hours := int(uptime.Hours()) % 24
		minutes := int(uptime.Minutes()) % 60
		sb.WriteString(fmt.Sprintf("Uptime:        %dd %dh %dm\n", days, hours, minutes))
		bootTime := time.Now().Add(-uptime)
		sb.WriteString(fmt.Sprintf("Boot Time:     %s\n", bootTime.Format("2006-01-02 15:04:05")))
	}

	// Check if elevated
	token := windows.GetCurrentProcessToken()
	isElevated := token.IsElevated()
	sb.WriteString(fmt.Sprintf("Elevated:      %v\n", isElevated))

	// .NET versions installed
	sb.WriteString("\n--- .NET Framework ---\n")
	netKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full`, registry.QUERY_VALUE)
	if err == nil {
		defer netKey.Close()
		release, _, err := netKey.GetIntegerValue("Release")
		if err == nil {
			sb.WriteString(fmt.Sprintf(".NET 4.x:      %s (release %d)\n",
				dotNetVersionFromRelease(release), release))
		}
	}
}

func dotNetVersionFromRelease(release uint64) string {
	switch {
	case release >= 533320:
		return "4.8.1+"
	case release >= 528040:
		return "4.8"
	case release >= 461808:
		return "4.7.2"
	case release >= 461308:
		return "4.7.1"
	case release >= 460798:
		return "4.7"
	case release >= 394802:
		return "4.6.2"
	case release >= 394254:
		return "4.6.1"
	case release >= 393295:
		return "4.6"
	case release >= 379893:
		return "4.5.2"
	case release >= 378675:
		return "4.5.1"
	case release >= 378389:
		return "4.5"
	default:
		return fmt.Sprintf("4.x (%d)", release)
	}
}
