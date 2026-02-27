package commands

import (
	"fmt"
	"syscall"
	"unsafe"
)

func getMountInfo() ([]mountInfoEntry, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getLogicalDrives := kernel32.NewProc("GetLogicalDrives")
	getDriveTypeW := kernel32.NewProc("GetDriveTypeW")
	getVolumeInformationW := kernel32.NewProc("GetVolumeInformationW")

	mask, _, _ := getLogicalDrives.Call()
	if mask == 0 {
		return nil, fmt.Errorf("GetLogicalDrives failed")
	}

	var entries []mountInfoEntry
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}

		drive := fmt.Sprintf("%c:\\", 'A'+i)
		drivePtr, _ := syscall.UTF16PtrFromString(drive)

		driveType, _, _ := getDriveTypeW.Call(uintptr(unsafe.Pointer(drivePtr)))

		dtStr := "unknown"
		switch driveType {
		case 0:
			dtStr = "unknown"
		case 1:
			dtStr = "no_root_dir"
		case 2:
			dtStr = "removable"
		case 3:
			dtStr = "fixed"
		case 4:
			dtStr = "network"
		case 5:
			dtStr = "cdrom"
		case 6:
			dtStr = "ramdisk"
		}

		// Get volume info
		var fsNameBuf [256]uint16
		var volNameBuf [256]uint16
		var flags uint32
		ret, _, _ := getVolumeInformationW.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			uintptr(unsafe.Pointer(&volNameBuf[0])),
			uintptr(len(volNameBuf)),
			0,
			0,
			uintptr(unsafe.Pointer(&flags)),
			uintptr(unsafe.Pointer(&fsNameBuf[0])),
			uintptr(len(fsNameBuf)),
		)
		fstype := "unknown"
		volName := ""
		if ret != 0 {
			fstype = syscall.UTF16ToString(fsNameBuf[:])
			volName = syscall.UTF16ToString(volNameBuf[:])
		}

		device := drive
		if volName != "" {
			device = fmt.Sprintf("%s [%s]", drive, volName)
		}

		entries = append(entries, mountInfoEntry{
			device:   device,
			mntPoint: drive,
			mntType:  fstype,
			mntOpts:  dtStr,
		})
	}

	return entries, nil
}
