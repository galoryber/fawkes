//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/binutil"
	"github.com/RIscRIpt/pecoff/windef"
	"golang.org/x/sys/windows"
)

// Custom COFF loader with fixed Beacon API implementations
// Based on goffloader but with GC-safe BeaconDataExtract

const (
	IMAGE_SCN_MEM_EXECUTE = 0x20000000
	PAGE_EXECUTE_READ     = windows.PAGE_EXECUTE_READ
	PAGE_READWRITE        = windows.PAGE_READWRITE
)

type coffSection struct {
	Section *pecoff.Section
	Address uintptr
}

// LoadAndRunBOF loads a COFF/BOF file and executes it with the given arguments
func LoadAndRunBOF(coffBytes []byte, argBytes []byte, entryPoint string) (string, error) {
	outputChan := make(chan interface{}, 100)

	parsedCoff := pecoff.Explore(binutil.WrapByteSlice(coffBytes))
	parsedCoff.ReadAll()
	parsedCoff.Seal()

	sections := make(map[string]coffSection, parsedCoff.Sections.Len())

	gotBaseAddress := uintptr(0)
	gotOffset := 0
	gotSize := uint32(0)
	var gotMap = make(map[string]uintptr)

	bssBaseAddress := uintptr(0)
	bssOffset := 0
	bssSize := uint32(0)

	// Calculate sizes for special sections
	for _, symbol := range parsedCoff.Symbols {
		if isSpecialSymbol(symbol) {
			if isImportSymbol(symbol) {
				gotSize += 8
			} else {
				bssSize += symbol.Value + 8
			}
		}
	}

	// Allocate memory for each section
	for _, section := range parsedCoff.Sections.Array() {
		allocationSize := uintptr(section.SizeOfRawData)
		if strings.HasPrefix(section.NameString(), ".bss") {
			allocationSize = uintptr(bssSize)
		}

		if allocationSize == 0 {
			continue
		}

		addr, err := virtualAllocBytes(uint32(allocationSize))
		if err != nil {
			return "", fmt.Errorf("VirtualAlloc failed: %v", err)
		}

		if strings.HasPrefix(section.NameString(), ".bss") {
			bssBaseAddress = addr
		}

		// Copy section data
		copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:], section.RawData())

		sections[section.NameString()] = coffSection{
			Section: section,
			Address: addr,
		}
	}

	// Allocate GOT
	gotBaseAddress, err := virtualAllocBytes(gotSize)
	if err != nil {
		return "", fmt.Errorf("VirtualAlloc for GOT failed: %v", err)
	}

	// Process relocations
	for _, section := range parsedCoff.Sections.Array() {
		sectionVirtualAddr := sections[section.NameString()].Address

		for _, reloc := range section.Relocations() {
			symbol := parsedCoff.Symbols[reloc.SymbolTableIndex]

			if symbol.StorageClass > 3 {
				continue
			}

			symbolDefAddress := uintptr(0)

			if isSpecialSymbol(symbol) {
				if isImportSymbol(symbol) {
					externalAddress := resolveExternalSymbol(symbol.NameString(), outputChan)

					if externalAddress == 0 {
						return "", fmt.Errorf("failed to resolve external symbol: %s", symbol.NameString())
					}

					if existingGotAddress, exists := gotMap[symbol.NameString()]; exists {
						symbolDefAddress = existingGotAddress
					} else {
						symbolDefAddress = gotBaseAddress + uintptr(gotOffset*8)
						gotOffset++
						gotMap[symbol.NameString()] = symbolDefAddress
					}
					*(*uint64)(unsafe.Pointer(symbolDefAddress)) = uint64(externalAddress)
				} else {
					symbolDefAddress = bssBaseAddress + uintptr(bssOffset)
					bssOffset += int(symbol.Value) + 8
				}
			} else {
				targetSection := parsedCoff.Sections.Array()[symbol.SectionNumber-1]
				symbolDefAddress = sections[targetSection.NameString()].Address + uintptr(symbol.Value)
			}

			processReloc(symbolDefAddress, sectionVirtualAddr, reloc, symbol)
		}

		// Set executable sections to PAGE_EXECUTE_READ
		if section.Characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
			var oldProtect uint32
			windows.VirtualProtect(sectionVirtualAddr, uintptr(section.SizeOfRawData), PAGE_EXECUTE_READ, &oldProtect)
		}
	}

	// Find and call entry point
	go func() {
		defer close(outputChan)
		defer func() {
			if r := recover(); r != nil {
				outputChan <- fmt.Sprintf("BOF panic: %v", r)
			}
		}()

		for _, symbol := range parsedCoff.Symbols {
			if symbol.NameString() == entryPoint {
				mainSection := parsedCoff.Sections.Array()[symbol.SectionNumber-1]
				entryAddr := sections[mainSection.NameString()].Address + uintptr(symbol.Value)

				if len(argBytes) == 0 {
					argBytes = make([]byte, 1)
				}
				syscall.SyscallN(entryAddr, uintptr(unsafe.Pointer(&argBytes[0])), uintptr(len(argBytes)))
				return
			}
		}
		outputChan <- fmt.Sprintf("Entry point '%s' not found", entryPoint)
	}()

	// Collect output
	var output string
	for msg := range outputChan {
		output += fmt.Sprintf("%v\n", msg)
	}

	return output, nil
}

func isSpecialSymbol(sym *pecoff.Symbol) bool {
	return sym.StorageClass == windef.IMAGE_SYM_CLASS_EXTERNAL && sym.SectionNumber == 0
}

func isImportSymbol(sym *pecoff.Symbol) bool {
	return strings.HasPrefix(sym.NameString(), "__imp_")
}

func resolveExternalSymbol(symbolName string, outChannel chan<- interface{}) uintptr {
	if !strings.HasPrefix(symbolName, "__imp_") {
		return 0
	}

	symbolName = symbolName[6:] // Remove "__imp_" prefix
	if strings.HasPrefix(symbolName, "_") {
		symbolName = symbolName[1:]
	}

	// Check for Beacon API functions - use OUR implementations
	switch symbolName {
	case "BeaconOutput":
		return windows.NewCallback(getBeaconOutputCallback(outChannel))
	case "BeaconDataParse":
		return windows.NewCallback(BeaconDataParse)
	case "BeaconDataInt":
		return windows.NewCallback(BeaconDataInt)
	case "BeaconDataShort":
		return windows.NewCallback(BeaconDataShort)
	case "BeaconDataLength":
		return windows.NewCallback(BeaconDataLength)
	case "BeaconDataExtract":
		return windows.NewCallback(BeaconDataExtract) // Our fixed version!
	case "BeaconPrintf":
		return windows.NewCallback(getBeaconPrintfCallback(outChannel))
	}

	// Dynamic Function Resolution (Library$Function format)
	if strings.Contains(symbolName, "$") {
		parts := strings.Split(symbolName, "$")
		libName := parts[0] + ".dll"
		procName := parts[1]

		lib, err := syscall.LoadLibrary(libName)
		if err != nil {
			return 0
		}
		proc, err := syscall.GetProcAddress(lib, procName)
		if err != nil {
			return 0
		}
		return proc
	}

	// Standard library functions
	var libName string
	switch symbolName {
	case "FreeLibrary", "LoadLibraryA", "GetProcAddress", "GetModuleHandleA":
		libName = "kernel32.dll"
	case "MessageBoxA":
		libName = "user32.dll"
	default:
		return 0
	}

	lib, err := syscall.LoadLibrary(libName)
	if err != nil {
		return 0
	}
	proc, err := syscall.GetProcAddress(lib, symbolName)
	if err != nil {
		return 0
	}
	return proc
}

func getBeaconOutputCallback(ch chan<- interface{}) func(int, uintptr, int) uintptr {
	return func(outType int, data uintptr, length int) uintptr {
		if length <= 0 {
			return 0
		}
		out := make([]byte, length)
		for i := 0; i < length; i++ {
			out[i] = *(*byte)(unsafe.Pointer(data + uintptr(i)))
		}
		ch <- string(out)
		return 1
	}
}

func getBeaconPrintfCallback(ch chan<- interface{}) func(int, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) uintptr {
	return func(outType int, format uintptr, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) uintptr {
		formatStr := readCString(format)
		// Basic format string handling
		ch <- formatStr
		return 0
	}
}

func processReloc(symbolDefAddress uintptr, sectionAddress uintptr, reloc windef.Relocation, symbol *pecoff.Symbol) {
	symbolOffset := uintptr(reloc.VirtualAddress)
	absoluteSymbolAddress := symbolOffset + sectionAddress
	segmentValue := *(*uint32)(unsafe.Pointer(absoluteSymbolAddress))

	if (symbol.StorageClass == windef.IMAGE_SYM_CLASS_STATIC && symbol.Value != 0) ||
		(symbol.StorageClass == windef.IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber != 0) {
		symbolOffset = uintptr(symbol.Value)
	} else {
		symbolDefAddress += uintptr(segmentValue)
	}

	switch reloc.Type {
	case windef.IMAGE_REL_AMD64_ADDR64:
		*(*uint64)(unsafe.Pointer(absoluteSymbolAddress)) = uint64(symbolDefAddress)
	case windef.IMAGE_REL_AMD64_ADDR32NB:
		valueToWrite := symbolDefAddress - (sectionAddress + 4 + symbolOffset)
		*(*uint32)(unsafe.Pointer(absoluteSymbolAddress)) = uint32(valueToWrite)
	case windef.IMAGE_REL_AMD64_REL32, windef.IMAGE_REL_AMD64_REL32_1, windef.IMAGE_REL_AMD64_REL32_2,
		windef.IMAGE_REL_AMD64_REL32_3, windef.IMAGE_REL_AMD64_REL32_4, windef.IMAGE_REL_AMD64_REL32_5:
		relativeAddr := symbolDefAddress - uintptr(reloc.Type-4) - (absoluteSymbolAddress + 4)
		*(*uint32)(unsafe.Pointer(absoluteSymbolAddress)) = uint32(relativeAddr)
	}
}
