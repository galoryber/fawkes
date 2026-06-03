//go:build darwin && arm64

package commands

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Dynamic imports from libSystem.B.dylib — resolved by the linker.
// The assembly trampolines in mach_darwin_arm64.s jump to these symbols.

//go:cgo_import_dynamic libc_mach_task_self_ mach_task_self_ "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_task_for_pid task_for_pid "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mach_vm_allocate mach_vm_allocate "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mach_vm_deallocate mach_vm_deallocate "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mach_vm_protect mach_vm_protect "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mach_vm_write mach_vm_write "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mach_port_deallocate mach_port_deallocate "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_ptrace ptrace "/usr/lib/libSystem.B.dylib"

// Trampoline addresses — filled at link time from the assembly GLOBL/DATA directives.
var libc_mach_task_self_trampoline_addr uintptr
var libc_task_for_pid_trampoline_addr uintptr
var libc_mach_vm_allocate_trampoline_addr uintptr
var libc_mach_vm_deallocate_trampoline_addr uintptr
var libc_mach_vm_protect_trampoline_addr uintptr
var libc_mach_vm_write_trampoline_addr uintptr
var libc_mach_port_deallocate_trampoline_addr uintptr
var libc_ptrace_trampoline_addr uintptr

// Mach VM constants
const (
	vmFlagsAnywhere = 1 // VM_FLAGS_ANYWHERE

	vmProtRead    = 1 // VM_PROT_READ
	vmProtWrite   = 2 // VM_PROT_WRITE
	vmProtExecute = 4 // VM_PROT_EXECUTE

	kernSuccess = 0 // KERN_SUCCESS
)

// machTaskSelf returns the current task's Mach port.
func machTaskSelf() uint32 {
	r1, _, _ := syscall.RawSyscall(libc_mach_task_self_trampoline_addr, 0, 0, 0)
	return uint32(r1)
}

// machTaskForPid gets the Mach task port for a given PID.
// Requires root or com.apple.security.cs.debugger entitlement.
func machTaskForPid(pid int) (uint32, error) {
	selfTask := machTaskSelf()
	var taskPort uint32
	r1, _, _ := syscall.RawSyscall(
		libc_task_for_pid_trampoline_addr,
		uintptr(selfTask),
		uintptr(pid),
		uintptr(unsafe.Pointer(&taskPort)),
	)
	kr := int32(r1)
	if kr != kernSuccess {
		return 0, fmt.Errorf("task_for_pid failed (kern_return=%d) — requires root or debugger entitlement", kr)
	}
	return taskPort, nil
}

// machVmAllocate allocates memory in a target task.
func machVmAllocate(task uint32, size uint64) (uint64, error) {
	var addr uint64
	r1, _, _ := syscall.Syscall6(
		libc_mach_vm_allocate_trampoline_addr,
		uintptr(task),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(size),
		uintptr(vmFlagsAnywhere),
		0, 0,
	)
	kr := int32(r1)
	if kr != kernSuccess {
		return 0, fmt.Errorf("mach_vm_allocate failed (kern_return=%d, size=%d)", kr, size)
	}
	return addr, nil
}

// machVmDeallocate frees memory in a target task.
func machVmDeallocate(task uint32, addr, size uint64) error {
	r1, _, _ := syscall.RawSyscall(
		libc_mach_vm_deallocate_trampoline_addr,
		uintptr(task),
		uintptr(addr),
		uintptr(size),
	)
	kr := int32(r1)
	if kr != kernSuccess {
		return fmt.Errorf("mach_vm_deallocate failed (kern_return=%d)", kr)
	}
	return nil
}

// machVmProtect changes memory protection in a target task.
func machVmProtect(task uint32, addr, size uint64, setMax bool, newProt int) error {
	setMaxInt := uintptr(0)
	if setMax {
		setMaxInt = 1
	}
	r1, _, _ := syscall.Syscall6(
		libc_mach_vm_protect_trampoline_addr,
		uintptr(task),
		uintptr(addr),
		uintptr(size),
		setMaxInt,
		uintptr(newProt),
		0,
	)
	kr := int32(r1)
	if kr != kernSuccess {
		return fmt.Errorf("mach_vm_protect failed (kern_return=%d, addr=0x%X, prot=%d)", kr, addr, newProt)
	}
	return nil
}

// machVmWrite writes data to a target task's address space.
func machVmWrite(task uint32, addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	r1, _, _ := syscall.Syscall6(
		libc_mach_vm_write_trampoline_addr,
		uintptr(task),
		uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0, 0,
	)
	kr := int32(r1)
	if kr != kernSuccess {
		return fmt.Errorf("mach_vm_write failed (kern_return=%d, addr=0x%X, size=%d)", kr, addr, len(data))
	}
	return nil
}

// rawPtrace calls ptrace(request, pid, addr, data) directly via libSystem.
// Go's syscall.PtraceDetach on darwin doesn't accept addr/data parameters,
// but we need them for PT_DETACH with PC redirect and PT_KILL.
func rawPtrace(request int, pid int, addr uintptr, data int) error {
	_, _, errno := syscall.Syscall6(
		libc_ptrace_trampoline_addr,
		uintptr(request),
		uintptr(pid),
		addr,
		uintptr(data),
		0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// machPortDeallocate releases a Mach port right.
func machPortDeallocate(task, port uint32) error {
	r1, _, _ := syscall.RawSyscall(
		libc_mach_port_deallocate_trampoline_addr,
		uintptr(task),
		uintptr(port),
		0,
	)
	kr := int32(r1)
	if kr != kernSuccess {
		return fmt.Errorf("mach_port_deallocate failed (kern_return=%d)", kr)
	}
	return nil
}
