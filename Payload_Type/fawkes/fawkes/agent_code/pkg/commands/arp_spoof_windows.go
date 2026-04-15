//go:build windows
// +build windows

package commands

import (
	"fawkes/pkg/structs"
)

// executeArpSpoof is a stub — Windows ARP spoofing requires WinPcap/Npcap.
func executeArpSpoof(task structs.Task) structs.CommandResult {
	return errorResult("ARP spoof not yet implemented on Windows. Requires WinPcap/Npcap for raw frame injection. Use Linux for ARP poisoning.")
}
