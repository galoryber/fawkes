//go:build windows

package commands

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sandboxCheckUptime checks system uptime via GetTickCount64.
func sandboxCheckUptime() sandboxCheck {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64 := kernel32.NewProc("GetTickCount64")

	ret, _, _ := getTickCount64.Call()
	uptimeMs := uint64(ret)
	uptime := time.Duration(uptimeMs) * time.Millisecond

	suspicious := uptime < 5*time.Minute
	score := 0
	if uptime < 2*time.Minute {
		score = 15
	} else if uptime < 5*time.Minute {
		score = 10
	}

	return sandboxCheck{
		Name:       "System Uptime",
		Category:   "timing",
		Suspicious: suspicious,
		Score:      score,
		Details:    fmt.Sprintf("%s", uptime.Truncate(time.Second)),
	}
}

// sandboxCheckRAM checks total physical RAM via GlobalMemoryStatusEx.
func sandboxCheckRAM() sandboxCheck {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")

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

	var memStatus memoryStatusEx
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))

	ret, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret == 0 {
		return sandboxCheck{Name: "Total RAM", Category: "hardware", Details: "unable to determine"}
	}

	gb := float64(memStatus.TotalPhys) / (1024 * 1024 * 1024)
	suspicious := gb < 2.0
	score := 0
	if gb < 1.0 {
		score = 15
	} else if gb < 2.0 {
		score = 10
	}

	return sandboxCheck{
		Name:       "Total RAM",
		Category:   "hardware",
		Suspicious: suspicious,
		Score:      score,
		Details:    fmt.Sprintf("%.1f GB", gb),
	}
}

// sandboxCheckDisk checks total disk space via GetDiskFreeSpaceExW.
func sandboxCheckDisk() sandboxCheck {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")

	rootPath, _ := windows.UTF16PtrFromString("C:\\")
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64

	ret, _, _ := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(rootPath)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if ret == 0 {
		return sandboxCheck{Name: "Disk Size", Category: "hardware", Details: "unable to determine"}
	}

	totalGB := float64(totalBytes) / (1024 * 1024 * 1024)
	suspicious := totalGB < 50.0
	score := 0
	if totalGB < 20.0 {
		score = 15
	} else if totalGB < 50.0 {
		score = 10
	}

	return sandboxCheck{
		Name:       "Disk Size",
		Category:   "hardware",
		Suspicious: suspicious,
		Score:      score,
		Details:    fmt.Sprintf("%.0f GB total", totalGB),
	}
}

// countProcesses counts running processes via NtQuerySystemInformation snapshot.
func countProcesses() int {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = windows.Process32First(snapshot, &pe32)
	if err != nil {
		return 0
	}

	count := 1
	for {
		err = windows.Process32Next(snapshot, &pe32)
		if err != nil {
			break
		}
		count++
	}
	return count
}
