//go:build darwin

package commands

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func enumerateRoutes() ([]RouteEntry, error) {
	// Use netstat -rn to get routing table on macOS
	// This is a common approach since macOS doesn't expose /proc/net/route
	out, err := exec.Command("netstat", "-rn").Output()
	if err != nil {
		return nil, fmt.Errorf("netstat -rn failed: %v", err)
	}

	return parseNetstatRoutes(string(out))
}

func parseNetstatRoutes(output string) ([]RouteEntry, error) {
	var routes []RouteEntry
	lines := strings.Split(output, "\n")

	inTable := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for the routing table header
		if strings.HasPrefix(line, "Destination") {
			inTable = true
			continue
		}
		if strings.HasPrefix(line, "Internet") || strings.HasPrefix(line, "Routing") {
			continue
		}

		if !inTable {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		dest := fields[0]
		gw := fields[1]
		flags := fields[2]
		iface := fields[len(fields)-1] // Interface is typically last field

		// Determine netmask from destination (CIDR notation or default)
		mask := "-"
		if strings.Contains(dest, "/") {
			parts := strings.SplitN(dest, "/", 2)
			dest = parts[0]
			_, ipNet, err := net.ParseCIDR(parts[0] + "/" + parts[1])
			if err == nil {
				mask = net.IP(ipNet.Mask).String()
			}
		} else if dest == "default" {
			mask = "0.0.0.0"
		}

		routes = append(routes, RouteEntry{
			Destination: dest,
			Gateway:     gw,
			Netmask:     mask,
			Interface:   iface,
			Flags:       flags,
		})
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("no routes parsed from netstat output")
	}

	return routes, nil
}
