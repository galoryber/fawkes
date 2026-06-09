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

const (
	beaconCallbackOutput     = 0x00
	beaconCallbackError      = 0x0d
	beaconCallbackOutputOEM  = 0x1e
	beaconCallbackOutputUTF8 = 0x20
)

type bofOutputMsg struct {
	outType int
	text    string
}

type coffSection struct {
	Section *pecoff.Section
	Address uintptr
}

type coffMemory struct {
	sections     map[string]coffSection
	gotBase      uintptr
	trampBase    uintptr
	gotSize      uint32
	trampSize    uint32
	trampOffset  int
}

func (cm *coffMemory) free() {
	for _, sec := range cm.sections {
		windows.VirtualFree(sec.Address, 0, windows.MEM_RELEASE)
	}
	if cm.gotBase != 0 {
		windows.VirtualFree(cm.gotBase, 0, windows.MEM_RELEASE)
	}
	if cm.trampBase != 0 {
		windows.VirtualFree(cm.trampBase, 0, windows.MEM_RELEASE)
	}
}

// LoadAndRunBOF loads a COFF/BOF file and executes it with the given arguments.
func LoadAndRunBOF(coffBytes []byte, argBytes []byte, entryPoint string, timeoutSec int) (string, error) {
	outputChan := make(chan interface{}, 100)

	parsedCoff := pecoff.Explore(binutil.WrapByteSlice(coffBytes))
	parsedCoff.ReadAll()
	parsedCoff.Seal()

	mem, bssBase, bssSize, err := coffAllocateSections(parsedCoff)
	if err != nil {
		return "", err
	}

	if err := coffProcessRelocations(parsedCoff, mem, bssBase, bssSize, outputChan); err != nil {
		return "", err
	}

	if err := coffFinalizePermissions(parsedCoff, mem); err != nil {
		return "", err
	}

	go coffRunEntry(parsedCoff, mem.sections, entryPoint, argBytes, outputChan)

	output, timedOut := coffCollectOutput(outputChan, timeoutSec)
	if !timedOut {
		mem.free()
	}
	return output, nil
}

func coffAllocateSections(parsedCoff *pecoff.File) (*coffMemory, uintptr, uint32, error) {
	mem := &coffMemory{
		sections: make(map[string]coffSection, parsedCoff.Sections.Len()),
	}
	var bssBase uintptr
	var bssSize uint32

	for _, symbol := range parsedCoff.Symbols {
		if isSpecialSymbol(symbol) {
			if isImportSymbol(symbol) {
				mem.gotSize += 8
			} else {
				mem.trampSize += 16
				bssSize += symbol.Value + 8
			}
		}
	}

	for _, section := range parsedCoff.Sections.Array() {
		allocationSize := uintptr(section.SizeOfRawData)
		if strings.HasPrefix(section.NameString(), ".bss") {
			allocationSize = uintptr(bssSize)
		}
		if allocationSize == 0 {
			continue
		}

		addr, err := virtualAllocRW(uint32(allocationSize))
		if err != nil {
			return nil, 0, 0, fmt.Errorf("memory allocation failed for section %s: %w", section.NameString(), err)
		}
		if strings.HasPrefix(section.NameString(), ".bss") {
			bssBase = addr
		}

		rawData := section.RawData()
		if uintptr(len(rawData)) > allocationSize {
			return nil, 0, 0, fmt.Errorf("section %s raw data (%d bytes) exceeds allocation (%d bytes)", section.NameString(), len(rawData), allocationSize)
		}
		if len(rawData) > 0 {
			copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:allocationSize], rawData)
		}
		mem.sections[section.NameString()] = coffSection{Section: section, Address: addr}
	}

	if mem.gotSize == 0 {
		mem.gotSize = 8
	}
	mem.gotBase, _ = virtualAllocRW(mem.gotSize)
	if mem.gotBase == 0 {
		return nil, 0, 0, fmt.Errorf("GOT memory allocation failed")
	}
	if mem.trampSize == 0 {
		mem.trampSize = 16
	}
	var err error
	mem.trampBase, err = virtualAllocRW(mem.trampSize)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("trampoline memory allocation failed: %w", err)
	}

	return mem, bssBase, bssSize, nil
}

func coffProcessRelocations(parsedCoff *pecoff.File, mem *coffMemory, bssBase uintptr, bssSize uint32, outputChan chan interface{}) error {
	gotMap := make(map[string]uintptr)
	trampolineMap := make(map[string]uintptr)
	gotOffset := 0
	bssOffset := 0

	for _, section := range parsedCoff.Sections.Array() {
		sectionVirtualAddr := mem.sections[section.NameString()].Address
		for _, reloc := range section.Relocations() {
			symbol := parsedCoff.Symbols[reloc.SymbolTableIndex]
			if symbol.StorageClass > 3 {
				continue
			}

			symbolDefAddress := uintptr(0)
			if isSpecialSymbol(symbol) {
				externalAddress := resolveExternalSymbol(symbol.NameString(), outputChan)

				if externalAddress != 0 && isImportSymbol(symbol) {
					if existingAddr, exists := gotMap[symbol.NameString()]; exists {
						symbolDefAddress = existingAddr
					} else {
						if uintptr(gotOffset*8+8) > uintptr(mem.gotSize) {
							return fmt.Errorf("GOT overflow: offset %d exceeds allocated size %d", gotOffset*8+8, mem.gotSize)
						}
						symbolDefAddress = mem.gotBase + uintptr(gotOffset*8)
						gotOffset++
						gotMap[symbol.NameString()] = symbolDefAddress
					}
					*(*uint64)(unsafe.Pointer(symbolDefAddress)) = uint64(externalAddress)
				} else if externalAddress != 0 {
					if existingAddr, exists := trampolineMap[symbol.NameString()]; exists {
						symbolDefAddress = existingAddr
					} else {
						trampAddr := mem.trampBase + uintptr(mem.trampOffset)
						*(*[6]byte)(unsafe.Pointer(trampAddr)) = [6]byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}
						*(*uint64)(unsafe.Pointer(trampAddr + 6)) = uint64(externalAddress)
						trampolineMap[symbol.NameString()] = trampAddr
						mem.trampOffset += 16
						symbolDefAddress = trampAddr
					}
				} else if isImportSymbol(symbol) {
					return fmt.Errorf("failed to resolve external symbol: %s", symbol.NameString())
				} else {
					if uintptr(bssOffset)+uintptr(symbol.Value)+8 > uintptr(bssSize) {
						return fmt.Errorf("BSS overflow: offset %d + size %d exceeds allocated %d", bssOffset, symbol.Value+8, bssSize)
					}
					symbolDefAddress = bssBase + uintptr(bssOffset)
					bssOffset += int(symbol.Value) + 8
				}
			} else {
				if int(symbol.SectionNumber) < 1 || int(symbol.SectionNumber) > parsedCoff.Sections.Len() {
					return fmt.Errorf("symbol %s references invalid section %d", symbol.NameString(), symbol.SectionNumber)
				}
				targetSection := parsedCoff.Sections.Array()[symbol.SectionNumber-1]
				symbolDefAddress = mem.sections[targetSection.NameString()].Address + uintptr(symbol.Value)
			}
			processReloc(symbolDefAddress, sectionVirtualAddr, reloc, symbol)
		}
	}
	return nil
}

func coffFinalizePermissions(parsedCoff *pecoff.File, mem *coffMemory) error {
	if mem.trampOffset > 0 {
		if err := virtualProtectRX(mem.trampBase, uint32(mem.trampOffset)); err != nil {
			return fmt.Errorf("trampoline protection change failed: %w", err)
		}
		flushInstructionCache(mem.trampBase, uint32(mem.trampOffset))
	}
	for _, section := range parsedCoff.Sections.Array() {
		if section.Characteristics&coffImageScnMemExecute != 0 {
			sec, ok := mem.sections[section.NameString()]
			if !ok || sec.Address == 0 || section.SizeOfRawData == 0 {
				continue
			}
			if err := virtualProtectRX(sec.Address, section.SizeOfRawData); err != nil {
				return fmt.Errorf("protection change failed for section %s: %w", section.NameString(), err)
			}
			flushInstructionCache(sec.Address, section.SizeOfRawData)
		}
	}
	return nil
}

func coffRunEntry(parsedCoff *pecoff.File, sections map[string]coffSection, entryPoint string, argBytes []byte, outputChan chan interface{}) {
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
}

func coffCollectOutput(outputChan chan interface{}, timeoutSec int) (string, bool) {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	var outputBuf strings.Builder
	deadline := time.After(time.Duration(timeoutSec) * time.Second)
	for {
		select {
		case msg, ok := <-outputChan:
			if !ok {
				return outputBuf.String(), false
			}
			switch m := msg.(type) {
			case bofOutputMsg:
				if m.outType == beaconCallbackError {
					fmt.Fprintf(&outputBuf, "[ERROR] %s\n", m.text)
				} else {
					fmt.Fprintf(&outputBuf, "%s\n", m.text)
				}
			default:
				fmt.Fprintf(&outputBuf, "%v\n", msg)
			}
		case <-deadline:
			fmt.Fprintf(&outputBuf, "[!] BOF execution timed out after %d seconds\n", timeoutSec)
			return outputBuf.String(), true
		}
	}
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
		ch <- bofOutputMsg{outType: outType, text: string(out)}
		return 1
	}
}

func getBeaconPrintfCallback(ch chan<- interface{}) func(int, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) uintptr {
	return func(outType int, format uintptr, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) uintptr {
		formatStr := readCString(format)
		ch <- bofOutputMsg{outType: outType, text: formatStr}
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
