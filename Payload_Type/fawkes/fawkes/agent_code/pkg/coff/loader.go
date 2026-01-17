//go:build windows
// +build windows

package coff

import (
	"bytes"
	"debug/pe"
	"fmt"
	"syscall"
	"unsafe"
)

// Loader handles loading and executing COFF files
type Loader struct {
	coffData      []byte
	peFile        *pe.File
	sectionMem    map[int]uintptr
	symbols       map[string]uintptr
	outputBuffer  *bytes.Buffer
}

// NewLoader creates a new COFF loader
func NewLoader(coffData []byte) (*Loader, error) {
	// Parse the COFF file
	peFile, err := pe.NewFile(bytes.NewReader(coffData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse COFF: %w", err)
	}

	return &Loader{
		coffData:     coffData,
		peFile:       peFile,
		sectionMem:   make(map[int]uintptr),
		symbols:      make(map[string]uintptr),
		outputBuffer: new(bytes.Buffer),
	}, nil
}

// Load allocates memory and loads all sections
func (l *Loader) Load() error {
	l.outputBuffer.WriteString(fmt.Sprintf("[DEBUG] Loading %d sections\n", len(l.peFile.Sections)))
	
	// Allocate memory for each section
	for i, section := range l.peFile.Sections {
		// Determine the size to allocate - use VirtualSize for BSS sections
		allocSize := section.Size
		if allocSize == 0 && section.VirtualSize > 0 {
			allocSize = section.VirtualSize
		}
		
		// Even if size is 0, allocate at least 1 byte so relocations can reference it
		// This handles empty .bss sections that are still referenced by relocations
		if allocSize == 0 {
			allocSize = 1
		}
		
		l.outputBuffer.WriteString(fmt.Sprintf("[DEBUG] Section %d: '%s' Size=%d VirtualSize=%d AllocSize=%d\n",
			i, section.Name, section.Size, section.VirtualSize, allocSize))

		// Allocate RWX memory for the section
		addr, err := virtualAlloc(0, uintptr(allocSize), 0x3000, 0x40) // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
		if err != nil {
			return fmt.Errorf("failed to allocate memory for section %s: %w", section.Name, err)
		}

		// Copy section data if it exists (won't exist for BSS)
		data, err := section.Data()
		if err == nil && len(data) > 0 {
			// Copy to allocated memory
			for j := 0; j < len(data); j++ {
				*(*byte)(unsafe.Pointer(addr + uintptr(j))) = data[j]
			}
			l.outputBuffer.WriteString(fmt.Sprintf("[DEBUG] Copied %d bytes to section '%s' at 0x%x\n", len(data), section.Name, addr))
		} else {
			l.outputBuffer.WriteString(fmt.Sprintf("[DEBUG] Section '%s' is BSS/empty (no data to copy) at 0x%x\n", section.Name, addr))
		}
		// BSS sections are already zeroed by VirtualAlloc

		l.sectionMem[i] = addr
	}

	// Register Beacon API functions
	l.registerBeaconAPI()

	// Process relocations
	if err := l.processRelocations(); err != nil {
		return fmt.Errorf("failed to process relocations: %w", err)
	}

	return nil
}

// virtualAlloc wraps VirtualAlloc
func virtualAlloc(addr, size, allocType, protect uintptr) (uintptr, error) {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	defer kernel32.Release()

	proc := kernel32.MustFindProc("VirtualAlloc")
	ret, _, err := proc.Call(addr, size, allocType, protect)
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

// registerBeaconAPI registers the Beacon API callback functions
func (l *Loader) registerBeaconAPI() {
	// BeaconPrintf - our output capture function
	l.symbols["BeaconPrintf"] = syscall.NewCallback(l.beaconPrintf)
	l.symbols["BeaconOutput"] = syscall.NewCallback(l.beaconOutput)
	
	// BeaconDataParse functions - for parsing arguments
	l.symbols["BeaconDataParse"] = syscall.NewCallback(l.beaconDataParse)
	l.symbols["BeaconDataInt"] = syscall.NewCallback(l.beaconDataInt)
	l.symbols["BeaconDataShort"] = syscall.NewCallback(l.beaconDataShort)
	l.symbols["BeaconDataExtract"] = syscall.NewCallback(l.beaconDataExtract)
	
	// Other common Beacon APIs (minimal implementation)
	l.symbols["BeaconFormatAlloc"] = syscall.NewCallback(l.beaconFormatAlloc)
	l.symbols["BeaconFormatPrintf"] = syscall.NewCallback(l.beaconFormatPrintf)
	l.symbols["BeaconFormatFree"] = syscall.NewCallback(l.beaconFormatFree)
}

// Execute runs the COFF entry point with the given arguments
func (l *Loader) Execute(entryPoint string, args []byte) (string, error) {
	// Find the entry point symbol
	var entryAddr uintptr
	for _, sym := range l.peFile.Symbols {
		if sym.Name == entryPoint {
			sectionNum := int(sym.SectionNumber) - 1
			if addr, ok := l.sectionMem[sectionNum]; ok {
				entryAddr = addr + uintptr(sym.Value)
				break
			}
		}
	}

	if entryAddr == 0 {
		return "", fmt.Errorf("entry point %s not found", entryPoint)
	}

	// Call the entry point with arguments
	argPtr := uintptr(0)
	argLen := uintptr(0)
	if len(args) > 0 {
		argPtr = uintptr(unsafe.Pointer(&args[0]))
		argLen = uintptr(len(args))
	}

	l.outputBuffer.WriteString(fmt.Sprintf("[DEBUG] Calling entry point at 0x%x with %d bytes of args at 0x%x\\n", entryAddr, argLen, argPtr))

	// BOF entry point signature: void go(char* args, int len)
	// Use Syscall (not SyscallN) which properly handles Windows x64 calling convention
	// Arguments are passed in RCX, RDX for the first two parameters
	_, _, _ = syscall.Syscall(entryAddr, 2, argPtr, argLen, 0)

	return l.outputBuffer.String(), nil
}

// GetOutput returns the captured output
func (l *Loader) GetOutput() string {
	return l.outputBuffer.String()
}

// Free releases all allocated memory
func (l *Loader) Free() {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	defer kernel32.Release()
	proc := kernel32.MustFindProc("VirtualFree")

	for _, addr := range l.sectionMem {
		proc.Call(addr, 0, 0x8000) // MEM_RELEASE
	}
}
