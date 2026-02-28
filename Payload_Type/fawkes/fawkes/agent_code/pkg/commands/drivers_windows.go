//go:build windows

package commands

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	psapiDrv                     = windows.NewLazySystemDLL("psapi.dll")
	procEnumDeviceDrivers        = psapiDrv.NewProc("EnumDeviceDrivers")
	procGetDeviceDriverBaseNameW = psapiDrv.NewProc("GetDeviceDriverBaseNameW")
	procGetDeviceDriverFileNameW = psapiDrv.NewProc("GetDeviceDriverFileNameW")
)

func enumerateDrivers() ([]DriverInfo, error) {
	// First call to get required buffer size
	var needed uint32
	ret, _, err := procEnumDeviceDrivers.Call(
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("EnumDeviceDrivers size query failed: %v", err)
	}

	count := needed / uint32(unsafe.Sizeof(uintptr(0)))
	if count == 0 {
		return nil, nil
	}

	// Allocate buffer for driver base addresses
	bases := make([]uintptr, count)
	ret, _, err = procEnumDeviceDrivers.Call(
		uintptr(unsafe.Pointer(&bases[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("EnumDeviceDrivers failed: %v", err)
	}

	// Update count based on actual returned data
	count = needed / uint32(unsafe.Sizeof(uintptr(0)))

	var drivers []DriverInfo
	nameBuf := make([]uint16, 260)
	pathBuf := make([]uint16, 260)

	for i := uint32(0); i < count; i++ {
		base := bases[i]
		if base == 0 {
			continue
		}

		// Get base name
		n, _, _ := procGetDeviceDriverBaseNameW.Call(
			base,
			uintptr(unsafe.Pointer(&nameBuf[0])),
			260,
		)
		name := ""
		if n > 0 {
			name = windows.UTF16ToString(nameBuf[:n])
		}

		// Get file path
		n, _, _ = procGetDeviceDriverFileNameW.Call(
			base,
			uintptr(unsafe.Pointer(&pathBuf[0])),
			260,
		)
		path := ""
		if n > 0 {
			path = windows.UTF16ToString(pathBuf[:n])
		}

		if name == "" && path == "" {
			continue
		}

		drivers = append(drivers, DriverInfo{
			Name:   name,
			Path:   path,
			Status: "loaded",
		})
	}

	return drivers, nil
}
