package commands

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
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

// Execute executes the arp command
func (c *ArpCommand) Execute(task structs.Task) structs.CommandResult {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("arp", "-a")
	case "darwin":
		cmd = exec.Command("arp", "-a")
	default: // linux
		// Try ip neigh first (modern), fall back to arp
		cmd = exec.Command("ip", "neigh", "show")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// On Linux, if ip neigh fails, try arp -a
		if runtime.GOOS == "linux" {
			cmd2 := exec.Command("arp", "-a")
			output2, err2 := cmd2.CombinedOutput()
			if err2 == nil && len(output2) > 0 {
				return formatArpOutput(string(output2))
			}
		}
		// If we got output despite the error, still return it
		if len(output) > 0 {
			return formatArpOutput(string(output))
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error running ARP command: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return formatArpOutput(string(output))
}

func formatArpOutput(raw string) structs.CommandResult {
	// Count unique entries
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	entryCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Interface") || strings.HasPrefix(line, "Internet") {
			continue
		}
		// Check if line contains a MAC-like pattern
		if containsMAC(line) {
			entryCount++
		}
	}

	output := raw
	if entryCount > 0 {
		output += fmt.Sprintf("\n[%d ARP entries found]", entryCount)
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// containsMAC checks if a string contains something that looks like a MAC address
func containsMAC(s string) bool {
	// Look for patterns like xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx
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
