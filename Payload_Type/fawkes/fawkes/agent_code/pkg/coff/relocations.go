//go:build windows
// +build windows

package coff

import (
	"debug/pe"
	"fmt"
	"syscall"
	"unsafe"
)

// Relocation types for AMD64
const (
	IMAGE_REL_AMD64_ADDR64   = 0x0001
	IMAGE_REL_AMD64_ADDR32   = 0x0002
	IMAGE_REL_AMD64_ADDR32NB = 0x0003
	IMAGE_REL_AMD64_REL32    = 0x0004
	IMAGE_REL_AMD64_REL32_1  = 0x0005
	IMAGE_REL_AMD64_REL32_2  = 0x0006
	IMAGE_REL_AMD64_REL32_3  = 0x0007
	IMAGE_REL_AMD64_REL32_4  = 0x0008
	IMAGE_REL_AMD64_REL32_5  = 0x0009
)

// processRelocations applies all relocations in the COFF file
func (l *Loader) processRelocations() error {
	for secIdx, section := range l.peFile.Sections {
		sectionAddr, ok := l.sectionMem[secIdx]
		if !ok {
			continue
		}

		// Get relocations for this section
		relocations := section.Relocs
		if len(relocations) == 0 {
			continue
		}

		for _, reloc := range relocations {
			// Get the symbol being referenced
			if int(reloc.SymbolTableIndex) >= len(l.peFile.Symbols) {
				// Symbol index out of bounds - skip this relocation
				// This can happen with auxiliary symbol table entries
				continue
			}

			symbol := l.peFile.Symbols[reloc.SymbolTableIndex]
			symbolAddr, err := l.resolveSymbol(symbol)
			if err != nil {
				// Try to continue with zero address for unresolved symbols
				// Some relocations might not need resolution
				symbolAddr = 0
			}

			// Calculate the relocation target address
			targetAddr := sectionAddr + uintptr(reloc.VirtualAddress)

			// Apply the relocation based on type
			if err := l.applyRelocation(targetAddr, symbolAddr, reloc.Type, sectionAddr); err != nil {
				return fmt.Errorf("failed to apply relocation: %w", err)
			}
		}
	}

	return nil
}

// resolveSymbol resolves a symbol to its address
func (l *Loader) resolveSymbol(symbol *pe.Symbol) (uintptr, error) {
	// Check if it's a Beacon API function
	if addr, ok := l.symbols[symbol.Name]; ok {
		return addr, nil
	}

	// Check if it's a Windows API import: __imp_DLLNAME$FunctionName
	if len(symbol.Name) > 6 && symbol.Name[:6] == "__imp_" {
		return l.resolveWindowsAPI(symbol.Name[6:])
	}

	// Check if it's in a section
	if symbol.SectionNumber > 0 {
		secIdx := int(symbol.SectionNumber) - 1
		if addr, ok := l.sectionMem[secIdx]; ok {
			return addr + uintptr(symbol.Value), nil
		}
	}

	// External symbol not found
	return 0, fmt.Errorf("unresolved symbol: %s", symbol.Name)
}

// resolveWindowsAPI resolves a Windows API function
// Format: DLLNAME$FunctionName (e.g., "KERNEL32$GetCurrentProcess")
func (l *Loader) resolveWindowsAPI(apiName string) (uintptr, error) {
	// Split on '$' to get DLL and function name
	parts := splitOnce(apiName, "$")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid API format: %s", apiName)
	}

	dllName := parts[0] + ".dll"
	funcName := parts[1]

	// Try to load the DLL
	dll, err := syscall.LoadDLL(dllName)
	if err != nil {
		return 0, fmt.Errorf("failed to load %s: %w", dllName, err)
	}
	// Note: We intentionally don't Release() the DLL as BOFs may call these functions

	// Find the procedure
	proc, err := dll.FindProc(funcName)
	if err != nil {
		return 0, fmt.Errorf("failed to find %s in %s: %w", funcName, dllName, err)
	}

	return proc.Addr(), nil
}

// splitOnce splits a string on the first occurrence of sep
func splitOnce(s, sep string) []string {
	idx := -1
	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			idx = i
			break
		}
	}
	if idx == -1 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+1:]}
}

// applyRelocation applies a relocation to memory
func (l *Loader) applyRelocation(targetAddr, symbolAddr uintptr, relocType uint16, sectionBase uintptr) error {
	switch relocType {
	case IMAGE_REL_AMD64_ADDR64:
		// 64-bit absolute address
		*(*uint64)(unsafe.Pointer(targetAddr)) = uint64(symbolAddr)

	case IMAGE_REL_AMD64_ADDR32:
		// 32-bit absolute address
		*(*uint32)(unsafe.Pointer(targetAddr)) = uint32(symbolAddr)

	case IMAGE_REL_AMD64_ADDR32NB:
		// 32-bit address without image base (RVA)
		rva := uint32(symbolAddr - sectionBase)
		*(*uint32)(unsafe.Pointer(targetAddr)) = rva

	case IMAGE_REL_AMD64_REL32, IMAGE_REL_AMD64_REL32_1, IMAGE_REL_AMD64_REL32_2,
		IMAGE_REL_AMD64_REL32_3, IMAGE_REL_AMD64_REL32_4, IMAGE_REL_AMD64_REL32_5:
		// 32-bit PC-relative
		offset := 0
		switch relocType {
		case IMAGE_REL_AMD64_REL32_1:
			offset = 1
		case IMAGE_REL_AMD64_REL32_2:
			offset = 2
		case IMAGE_REL_AMD64_REL32_3:
			offset = 3
		case IMAGE_REL_AMD64_REL32_4:
			offset = 4
		case IMAGE_REL_AMD64_REL32_5:
			offset = 5
		}

		// Calculate relative offset
		nextInstrAddr := targetAddr + 4
		rel := int32(symbolAddr - nextInstrAddr - uintptr(offset))
		*(*int32)(unsafe.Pointer(targetAddr)) = rel

	default:
		return fmt.Errorf("unsupported relocation type: 0x%x", relocType)
	}

	return nil
}
