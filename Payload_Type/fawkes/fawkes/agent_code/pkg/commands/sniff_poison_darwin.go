//go:build darwin
// +build darwin

package commands

import (
	"fawkes/pkg/structs"
)

// executePoison runs the LLMNR/NBT-NS/mDNS poisoner with HTTP NTLM capture on macOS.
// Note: Multicast UDP binding may require elevated privileges on macOS.
func (c *SniffCommand) executePoison(task structs.Task) structs.CommandResult {
	return executePoisonCore(task)
}
