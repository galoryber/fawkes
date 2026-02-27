package commands

import (
	"fmt"
	"syscall"
	"unsafe"
)

func getDiskFreeInfo() ([]dfEntry, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getLogicalDrives := kernel32.NewProc("GetLogicalDrives")
	getDiskFreeSpaceExW := kernel32.NewProc("GetDiskFreeSpaceExW")
	getDriveTypeW := kernel32.NewProc("GetDriveTypeW")
	getVolumeInformationW := kernel32.NewProc("GetVolumeInformationW")

	mask, _, _ := getLogicalDrives.Call()
	if mask == 0 {
		return nil, fmt.Errorf("GetLogicalDrives failed")
	}

	var entries []dfEntry
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}

		drive := fmt.Sprintf("%c:\\", 'A'+i)
		drivePtr, _ := syscall.UTF16PtrFromString(drive)

		driveType, _, _ := getDriveTypeW.Call(uintptr(unsafe.Pointer(drivePtr)))
		// Skip unknown (0), no root dir (1), and CD-ROM (5)
		if driveType == 0 || driveType == 1 || driveType == 5 {
			continue
		}

		var freeBytesAvailable, totalBytes, totalFreeBytes uint64
		ret, _, _ := getDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFreeBytes)),
		)
		if ret == 0 {
			continue
		}

		// Get filesystem type
		var fsNameBuf [256]uint16
		ret2, _, _ := getVolumeInformationW.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			0, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(&fsNameBuf[0])),
			uintptr(len(fsNameBuf)),
		)
		fstype := "unknown"
		if ret2 != 0 {
			fstype = syscall.UTF16ToString(fsNameBuf[:])
		}

		dtStr := "local"
		switch driveType {
		case 2:
			dtStr = "removable"
		case 3:
			dtStr = "fixed"
		case 4:
			dtStr = "network"
		case 6:
			dtStr = "ramdisk"
		}

		entries = append(entries, dfEntry{
			device:     fmt.Sprintf("%s (%s)", drive, dtStr),
			fstype:     fstype,
			mountpoint: drive,
			total:      totalBytes,
			used:       totalBytes - totalFreeBytes,
			avail:      freeBytesAvailable,
		})
	}

	return entries, nil
}
