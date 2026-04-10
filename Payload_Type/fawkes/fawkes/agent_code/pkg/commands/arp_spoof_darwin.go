//go:build darwin
// +build darwin

package commands

import (
	"fawkes/pkg/structs"
)

// executeArpSpoof is a stub — macOS ARP spoofing requires BPF device access.
func executeArpSpoof(task structs.Task) structs.CommandResult {
	return errorResult("ARP spoof not yet implemented on macOS. Requires /dev/bpf access for raw frame injection. Use Linux for ARP poisoning.")
}
