//go:build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapiRoute           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpForwardTable   = iphlpapiRoute.NewProc("GetIpForwardTable")
)

// MIB_IPFORWARDROW — IPv4 routing table entry
type mibIpForwardRow struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

func enumerateRoutes() ([]RouteEntry, error) {
	// First call to get buffer size
	var size uint32
	ret, _, _ := procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 1)
	if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && ret != 0 {
		return nil, fmt.Errorf("GetIpForwardTable size query failed: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetIpForwardTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, // sorted
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetIpForwardTable failed: %d", ret)
	}

	// Parse: first 4 bytes = dwNumEntries, then array of MIB_IPFORWARDROW
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := uint32(unsafe.Sizeof(mibIpForwardRow{}))

	// Get interface index→name mapping
	ifMap := getInterfaceNames()

	var routes []RouteEntry
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*rowSize
		if offset+rowSize > uint32(len(buf)) {
			break
		}

		row := (*mibIpForwardRow)(unsafe.Pointer(&buf[offset]))

		dest := ipv4ToString(row.ForwardDest)
		mask := ipv4ToString(row.ForwardMask)
		gw := ipv4ToString(row.ForwardNextHop)
		ifName := fmt.Sprintf("if%d", row.ForwardIfIndex)
		if name, ok := ifMap[row.ForwardIfIndex]; ok {
			ifName = name
		}

		flags := routeTypeString(row.ForwardType)

		routes = append(routes, RouteEntry{
			Destination: dest,
			Gateway:     gw,
			Netmask:     mask,
			Interface:   ifName,
			Metric:      row.ForwardMetric1,
			Flags:       flags,
		})
	}

	return routes, nil
}

func ipv4ToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF)
}

func routeTypeString(t uint32) string {
	switch t {
	case 1:
		return "other"
	case 2:
		return "invalid"
	case 3:
		return "direct"
	case 4:
		return "indirect"
	default:
		return fmt.Sprintf("type%d", t)
	}
}

func getInterfaceNames() map[uint32]string {
	ifMap := make(map[uint32]string)
	ifaces, err := net.Interfaces()
	if err != nil {
		return ifMap
	}
	for _, iface := range ifaces {
		ifMap[uint32(iface.Index)] = iface.Name
	}
	return ifMap
}
