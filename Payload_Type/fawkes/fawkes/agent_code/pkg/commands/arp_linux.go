//go:build linux

package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// getArpTable reads the ARP table from /proc/net/arp (no subprocess needed).
func getArpTable() ([]arpEntry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/net/arp: %w", err)
	}
	defer f.Close()

	var entries []arpEntry
	scanner := bufio.NewScanner(f)

	// Skip header line: "IP address  HW type  Flags  HW address  Mask  Device"
	if !scanner.Scan() {
		return entries, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		ip := fields[0]
		mac := fields[3]
		flags := fields[2]
		iface := fields[5]

		// Flags: 0x2 = complete, 0x4 = permanent, 0x0 = incomplete
		typeName := "dynamic"
		switch flags {
		case "0x0":
			typeName = "incomplete"
		case "0x4":
			typeName = "static"
		case "0x6":
			typeName = "static"
		}

		// Skip incomplete entries (00:00:00:00:00:00)
		if mac == "00:00:00:00:00:00" {
			continue
		}

		entries = append(entries, arpEntry{
			IP:        ip,
			MAC:       mac,
			Type:      typeName,
			Interface: iface,
		})
	}

	return entries, scanner.Err()
}
