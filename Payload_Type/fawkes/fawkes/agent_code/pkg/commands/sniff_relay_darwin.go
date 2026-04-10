//go:build darwin
// +build darwin

package commands

import (
	"fawkes/pkg/structs"
)

// executeRelay runs the NTLM relay server on macOS.
func (c *SniffCommand) executeRelay(task structs.Task) structs.CommandResult {
	return executeRelayCore(task)
}
