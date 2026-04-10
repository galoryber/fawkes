//go:build windows
// +build windows

package commands

import (
	"fawkes/pkg/structs"
)

// executeRelay runs the NTLM relay server on Windows.
func (c *SniffCommand) executeRelay(task structs.Task) structs.CommandResult {
	return executeRelayCore(task)
}
