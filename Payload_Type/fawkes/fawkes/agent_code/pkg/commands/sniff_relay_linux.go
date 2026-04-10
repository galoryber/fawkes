//go:build linux
// +build linux

package commands

import (
	"fawkes/pkg/structs"
)

// executeRelay runs the NTLM relay server on Linux.
func (c *SniffCommand) executeRelay(task structs.Task) structs.CommandResult {
	return executeRelayCore(task)
}
