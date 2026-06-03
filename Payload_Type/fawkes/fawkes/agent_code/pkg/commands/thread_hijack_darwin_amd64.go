//go:build darwin && amd64

package commands

import (
	"fawkes/pkg/structs"
)

type ThreadHijackCommand struct{}

func (c *ThreadHijackCommand) Name() string { return "thread-hijack" }
func (c *ThreadHijackCommand) Description() string {
	return "Thread execution hijacking — not yet implemented on macOS x86_64 (ARM64 only)"
}

type ThreadHijackParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
	TID          int    `json:"tid"`
}

func (c *ThreadHijackCommand) Execute(task structs.Task) structs.CommandResult {
	return errorResult("Error: thread hijack on macOS requires ARM64 (Apple Silicon). x86_64 support is not yet implemented.")
}
