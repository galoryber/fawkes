//go:build darwin
// +build darwin

package commands

import (
	"fawkes/pkg/structs"
)

// executePoison is a stub — macOS poison implementation in a future session.
func (c *SniffCommand) executePoison(task structs.Task) structs.CommandResult {
	return errorResult("Poison mode not yet implemented on macOS. Use Linux for LLMNR/NBT-NS poisoning.")
}
