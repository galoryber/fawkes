//go:build windows
// +build windows

package coff

import (
	"debug/pe"
	"fmt"
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
				return fmt.Errorf("invalid symbol index: %d", reloc.SymbolTableIndex)
			}

			symbol := l.peFile.Symbols[reloc.SymbolTableIndex]
			symbolAddr, err := l.resolveSymbol(symbol)
			if err != nil {
				return fmt.Errorf("failed to resolve symbol %s: %w", symbol.Name, err)
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
