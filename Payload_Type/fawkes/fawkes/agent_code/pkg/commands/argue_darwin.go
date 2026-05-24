//go:build darwin

package commands

import "fawkes/pkg/structs"

type ArgueCommand struct{}

func (c *ArgueCommand) Name() string { return "argue" }
func (c *ArgueCommand) Description() string {
	return "Execute a command with spoofed process arguments"
}

func (c *ArgueCommand) Execute(task structs.Task) structs.CommandResult {
	return errorResult("Error: argue is not yet supported on macOS (PEB manipulation requires mach_vm APIs)")
}
