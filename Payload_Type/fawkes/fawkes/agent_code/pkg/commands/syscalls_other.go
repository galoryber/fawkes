//go:build !windows

package commands

import "fawkes/pkg/structs"

// SyscallsCommand is a no-op on non-Windows platforms
type SyscallsCommand struct{}

func (c *SyscallsCommand) Name() string        { return "syscalls" }
func (c *SyscallsCommand) Description() string { return "Show indirect syscall resolver status (Windows only)" }

func (c *SyscallsCommand) Execute(task structs.Task) structs.CommandResult {
	return structs.CommandResult{Output: "Indirect syscalls are only supported on Windows", Status: "error", Completed: true}
}
