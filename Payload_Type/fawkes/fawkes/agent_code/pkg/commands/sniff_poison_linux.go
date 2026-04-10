//go:build linux
// +build linux

package commands

import (
	"fawkes/pkg/structs"
)

// executePoison runs the LLMNR/NBT-NS/mDNS poisoner with HTTP NTLM capture on Linux.
func (c *SniffCommand) executePoison(task structs.Task) structs.CommandResult {
	return executePoisonCore(task)
}
