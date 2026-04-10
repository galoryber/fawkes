//go:build windows
// +build windows

package commands

import (
	"fawkes/pkg/structs"
)

// executePoison is a stub — Windows poison implementation in a future session.
func (c *SniffCommand) executePoison(task structs.Task) structs.CommandResult {
	return errorResult("Poison mode not yet implemented on Windows. Use Linux for LLMNR/NBT-NS poisoning.")
}
