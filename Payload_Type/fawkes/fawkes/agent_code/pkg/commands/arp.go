package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"fawkes/pkg/structs"
)

// ArpCommand implements the arp command
type ArpCommand struct{}

// Name returns the command name
func (c *ArpCommand) Name() string {
	return "arp"
}

// Description returns the command description
func (c *ArpCommand) Description() string {
	return "Display ARP table — shows IP-to-MAC address mappings for nearby hosts (T1016.001)"
}

type arpArgs struct {
	IP        string `json:"ip"`        // filter by IP (substring match)
	MAC       string `json:"mac"`       // filter by MAC address (substring match)
	Interface string `json:"interface"` // filter by interface name (case-insensitive)
}

// Execute executes the arp command using platform-specific implementation
func (c *ArpCommand) Execute(task structs.Task) structs.CommandResult {
	var args arpArgs
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args)
	}

	entries, err := getArpTable()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading ARP table: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Apply filters
	if args.IP != "" || args.MAC != "" || args.Interface != "" {
		var filtered []arpEntry
		for _, e := range entries {
			if args.IP != "" && !strings.Contains(e.IP, args.IP) {
				continue
			}
			if args.MAC != "" && !strings.Contains(strings.ToLower(e.MAC), strings.ToLower(args.MAC)) {
				continue
			}
			if args.Interface != "" && !strings.EqualFold(e.Interface, args.Interface) {
				continue
			}
			filtered = append(filtered, e)
		}
		entries = filtered
	}

	if len(entries) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	jsonBytes, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshalling ARP table: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(jsonBytes),
		Status:    "success",
		Completed: true,
	}
}

// arpEntry represents a single ARP table entry
type arpEntry struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Type      string `json:"type"`
	Interface string `json:"interface"`
}

// containsMAC checks if a string contains something that looks like a MAC address
func containsMAC(s string) bool {
	parts := strings.Fields(s)
	for _, p := range parts {
		if isMACAddress(p) {
			return true
		}
	}
	return false
}

// isMACAddress checks if a string is a MAC address format
func isMACAddress(s string) bool {
	_, err := net.ParseMAC(s)
	return err == nil
}
