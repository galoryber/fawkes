//go:build darwin

package commands

import (
	"os/exec"
	"strings"
)

// getArpTable reads the ARP table using arp -a on macOS.
// macOS does not expose ARP entries via a file like Linux's /proc/net/arp,
// so subprocess is the practical approach.
func getArpTable() ([]arpEntry, error) {
	out, err := exec.Command("arp", "-a").CombinedOutput()
	if err != nil {
		return nil, err
	}

	var entries []arpEntry
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// macOS arp -a format: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
		// or: "hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[2] != "at" {
			continue
		}

		// Extract IP from parentheses
		ip := strings.Trim(fields[1], "()")
		mac := fields[3]

		// Skip incomplete entries
		if mac == "(incomplete)" {
			continue
		}

		// Interface is after "on"
		iface := ""
		for i, f := range fields {
			if f == "on" && i+1 < len(fields) {
				iface = fields[i+1]
				break
			}
		}

		entries = append(entries, arpEntry{
			IP:        ip,
			MAC:       mac,
			Type:      "dynamic",
			Interface: iface,
		})
	}

	return entries, nil
}
