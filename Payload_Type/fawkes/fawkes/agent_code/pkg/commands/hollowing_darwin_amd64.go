//go:build darwin && amd64

package commands

import (
	"fawkes/pkg/structs"
)

type HollowingCommand struct{}

func (c *HollowingCommand) Name() string { return "hollow" }
func (c *HollowingCommand) Description() string {
	return "Process hollowing — not yet implemented on macOS x86_64 (ARM64 only)"
}

func (c *HollowingCommand) Execute(task structs.Task) structs.CommandResult {
	return errorResult("Error: process hollowing on macOS requires ARM64 (Apple Silicon). x86_64 support is not yet implemented.")
}
