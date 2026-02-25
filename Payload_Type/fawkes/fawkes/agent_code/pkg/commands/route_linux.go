//go:build linux

package commands

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func enumerateRoutes() ([]RouteEntry, error) {
	// Parse /proc/net/route
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/net/route: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return nil, nil
	}

	var routes []RouteEntry
	// Skip header line
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		iface := fields[0]
		dest := hexToIP(fields[1])
		gw := hexToIP(fields[2])
		flagsVal, _ := strconv.ParseUint(fields[3], 16, 32)
		mask := hexToIP(fields[7])
		metric, _ := strconv.ParseUint(fields[6], 10, 32)

		flags := linuxRouteFlags(uint32(flagsVal))

		routes = append(routes, RouteEntry{
			Destination: dest,
			Gateway:     gw,
			Netmask:     mask,
			Interface:   iface,
			Metric:      uint32(metric),
			Flags:       flags,
		})
	}

	// Also try IPv6 from /proc/net/ipv6_route
	routes = append(routes, enumerateIPv6Routes()...)

	return routes, nil
}

func hexToIP(h string) string {
	if len(h) != 8 {
		return h
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 4 {
		return h
	}
	// /proc/net/route stores in host byte order (little-endian on x86)
	return net.IPv4(b[3], b[2], b[1], b[0]).String()
}

func linuxRouteFlags(f uint32) string {
	var flags []string
	if f&0x0001 != 0 {
		flags = append(flags, "U") // Up
	}
	if f&0x0002 != 0 {
		flags = append(flags, "G") // Gateway
	}
	if f&0x0004 != 0 {
		flags = append(flags, "H") // Host
	}
	if f&0x0008 != 0 {
		flags = append(flags, "R") // Reinstate
	}
	if f&0x0010 != 0 {
		flags = append(flags, "D") // Dynamic
	}
	if f&0x0020 != 0 {
		flags = append(flags, "M") // Modified
	}
	if len(flags) == 0 {
		return "-"
	}
	return strings.Join(flags, "")
}

func enumerateIPv6Routes() []RouteEntry {
	data, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return nil
	}

	var routes []RouteEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		dest := hexToIPv6(fields[0])
		destPrefix := fields[1]
		gw := hexToIPv6(fields[4])
		metric, _ := strconv.ParseUint(fields[5], 16, 32)
		iface := fields[9]

		routes = append(routes, RouteEntry{
			Destination: dest + "/" + destPrefixToLen(destPrefix),
			Gateway:     gw,
			Netmask:     "-",
			Interface:   iface,
			Metric:      uint32(metric),
			Flags:       "v6",
		})
	}
	return routes
}

func hexToIPv6(h string) string {
	if len(h) != 32 {
		return h
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 16 {
		return h
	}
	ip := net.IP(b)
	return ip.String()
}

func destPrefixToLen(h string) string {
	val, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return h
	}
	return strconv.FormatUint(val, 10)
}
