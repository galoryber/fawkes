//go:build windows
// +build windows

package commands

import (
	"fawkes/pkg/structs"
)

// executePoison runs the LLMNR/NBT-NS/mDNS poisoner with HTTP NTLM capture on Windows.
// Note: Port 137 (NBT-NS) may conflict with the Windows NetBIOS service.
// Port 80 may conflict with IIS or other web servers.
func (c *SniffCommand) executePoison(task structs.Task) structs.CommandResult {
	return executePoisonCore(task)
}
