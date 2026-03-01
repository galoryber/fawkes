//go:build windows

package commands

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi          = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable = iphlpapi.NewProc("GetIpNetTable")
)

// MIB_IPNETROW represents a single ARP entry from GetIpNetTable
type mibIPNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32 // IPv4 address in network byte order
	Type        uint32
}

const (
	arpTypeOther   = 1
	arpTypeInvalid = 2
	arpTypeDynamic = 3
	arpTypeStatic  = 4
)

// getArpTable reads the ARP table using the Win32 GetIpNetTable API.
func getArpTable() ([]arpEntry, error) {
	// First call to get required buffer size
	var size uint32
	ret, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && ret != 0 {
		return nil, fmt.Errorf("GetIpNetTable size query failed: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, // sorted by IP
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetIpNetTable failed: %d", ret)
	}

	// Parse the result: first 4 bytes are the number of entries
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	if numEntries == 0 {
		return nil, nil
	}

	rowSize := unsafe.Sizeof(mibIPNetRow{})
	entries := make([]arpEntry, 0, numEntries)

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		row := (*mibIPNetRow)(unsafe.Pointer(&buf[offset]))

		// Convert IP from uint32 (network byte order) to dotted string
		ip := net.IPv4(
			byte(row.Addr),
			byte(row.Addr>>8),
			byte(row.Addr>>16),
			byte(row.Addr>>24),
		)

		// Format MAC address
		mac := net.HardwareAddr(row.PhysAddr[:row.PhysAddrLen])

		// Get interface name from index
		ifName := fmt.Sprintf("if%d", row.Index)
		if iface, err := net.InterfaceByIndex(int(row.Index)); err == nil {
			ifName = iface.Name
		}

		// Map type
		typeName := "other"
		switch row.Type {
		case arpTypeDynamic:
			typeName = "dynamic"
		case arpTypeStatic:
			typeName = "static"
		case arpTypeInvalid:
			typeName = "invalid"
		}

		entries = append(entries, arpEntry{
			IP:        ip.String(),
			MAC:       mac.String(),
			Type:      typeName,
			Interface: ifName,
		})
	}

	return entries, nil
}
