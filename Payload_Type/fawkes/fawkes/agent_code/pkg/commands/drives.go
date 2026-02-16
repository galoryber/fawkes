//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
	"golang.org/x/sys/windows"
)

// DrivesCommand implements the drives command
type DrivesCommand struct{}

// Name returns the command name
func (c *DrivesCommand) Name() string {
	return "drives"
}

// Description returns the command description
func (c *DrivesCommand) Description() string {
	return "List available drives/volumes with type and free space (T1083)"
}

var (
	kernel32Drives          = windows.NewLazySystemDLL("kernel32.dll")
	procGetLogicalDrives    = kernel32Drives.NewProc("GetLogicalDrives")
	procGetDriveTypeW       = kernel32Drives.NewProc("GetDriveTypeW")
	procGetDiskFreeSpaceExW = kernel32Drives.NewProc("GetDiskFreeSpaceExW")
	procGetVolumeInfoW      = kernel32Drives.NewProc("GetVolumeInformationW")
)

// Execute executes the drives command
func (c *DrivesCommand) Execute(task structs.Task) structs.CommandResult {
	// Get logical drive bitmask
	mask, _, _ := procGetLogicalDrives.Call()
	if mask == 0 {
		return structs.CommandResult{
			Output:    "Error: GetLogicalDrives returned 0",
			Status:    "error",
			Completed: true,
		}
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("%-6s %-12s %-20s %15s %15s\n", "Drive", "Type", "Label", "Free (GB)", "Total (GB)"))
	output.WriteString(strings.Repeat("-", 72) + "\n")

	count := 0
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}

		driveLetter := string(rune('A'+i)) + ":\\"
		driveType := getDriveType(driveLetter)
		label := getVolumeLabel(driveLetter)
		freeGB, totalGB := getDiskSpace(driveLetter)

		freeStr := "-"
		totalStr := "-"
		if totalGB >= 0 {
			freeStr = fmt.Sprintf("%.1f", freeGB)
			totalStr = fmt.Sprintf("%.1f", totalGB)
		}

		output.WriteString(fmt.Sprintf("%-6s %-12s %-20s %15s %15s\n",
			driveLetter, driveType, label, freeStr, totalStr))
		count++
	}

	output.WriteString(fmt.Sprintf("\n[%d drives found]", count))

	return structs.CommandResult{
		Output:    output.String(),
		Status:    "success",
		Completed: true,
	}
}

func getDriveType(drive string) string {
	drivePtr, _ := syscall.UTF16PtrFromString(drive)
	ret, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(drivePtr)))
	switch ret {
	case 0:
		return "Unknown"
	case 1:
		return "No Root Dir"
	case 2:
		return "Removable"
	case 3:
		return "Fixed"
	case 4:
		return "Network"
	case 5:
		return "CD-ROM"
	case 6:
		return "RAM Disk"
	default:
		return "Unknown"
	}
}

func getVolumeLabel(drive string) string {
	drivePtr, _ := syscall.UTF16PtrFromString(drive)
	labelBuf := make([]uint16, 256)
	fsBuf := make([]uint16, 256)
	ret, _, _ := procGetVolumeInfoW.Call(
		uintptr(unsafe.Pointer(drivePtr)),
		uintptr(unsafe.Pointer(&labelBuf[0])),
		256,
		0, 0, 0,
		uintptr(unsafe.Pointer(&fsBuf[0])),
		256,
	)
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(labelBuf)
}

func getDiskSpace(drive string) (freeGB float64, totalGB float64) {
	drivePtr, _ := syscall.UTF16PtrFromString(drive)
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	ret, _, _ := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(drivePtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if ret == 0 {
		return -1, -1
	}
	return float64(freeBytesAvailable) / (1024 * 1024 * 1024), float64(totalBytes) / (1024 * 1024 * 1024)
}
