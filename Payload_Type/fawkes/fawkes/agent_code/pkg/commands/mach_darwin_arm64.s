// Mach API assembly trampolines for darwin/arm64.
// These trampoline functions jump to the corresponding libSystem symbols,
// which are resolved by the dynamic linker at load time. Each GLOBL/DATA
// pair exports the trampoline's address as a Go uintptr variable so that
// Go code can pass it to syscall.Syscall6.

#include "textflag.h"

// --- mach_task_self_ ---
TEXT libc_mach_task_self_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mach_task_self_(SB)
GLOBL	·libc_mach_task_self_trampoline_addr(SB), RODATA, $8
DATA	·libc_mach_task_self_trampoline_addr+0(SB)/8, $libc_mach_task_self_trampoline<>(SB)

// --- task_for_pid ---
TEXT libc_task_for_pid_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_task_for_pid(SB)
GLOBL	·libc_task_for_pid_trampoline_addr(SB), RODATA, $8
DATA	·libc_task_for_pid_trampoline_addr+0(SB)/8, $libc_task_for_pid_trampoline<>(SB)

// --- mach_vm_allocate ---
TEXT libc_mach_vm_allocate_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mach_vm_allocate(SB)
GLOBL	·libc_mach_vm_allocate_trampoline_addr(SB), RODATA, $8
DATA	·libc_mach_vm_allocate_trampoline_addr+0(SB)/8, $libc_mach_vm_allocate_trampoline<>(SB)

// --- mach_vm_deallocate ---
TEXT libc_mach_vm_deallocate_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mach_vm_deallocate(SB)
GLOBL	·libc_mach_vm_deallocate_trampoline_addr(SB), RODATA, $8
DATA	·libc_mach_vm_deallocate_trampoline_addr+0(SB)/8, $libc_mach_vm_deallocate_trampoline<>(SB)

// --- mach_vm_protect ---
TEXT libc_mach_vm_protect_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mach_vm_protect(SB)
GLOBL	·libc_mach_vm_protect_trampoline_addr(SB), RODATA, $8
DATA	·libc_mach_vm_protect_trampoline_addr+0(SB)/8, $libc_mach_vm_protect_trampoline<>(SB)

// --- mach_vm_write ---
TEXT libc_mach_vm_write_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mach_vm_write(SB)
GLOBL	·libc_mach_vm_write_trampoline_addr(SB), RODATA, $8
DATA	·libc_mach_vm_write_trampoline_addr+0(SB)/8, $libc_mach_vm_write_trampoline<>(SB)

// --- mach_port_deallocate ---
TEXT libc_mach_port_deallocate_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mach_port_deallocate(SB)
GLOBL	·libc_mach_port_deallocate_trampoline_addr(SB), RODATA, $8
DATA	·libc_mach_port_deallocate_trampoline_addr+0(SB)/8, $libc_mach_port_deallocate_trampoline<>(SB)

// --- ptrace ---
TEXT libc_ptrace_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_ptrace(SB)
GLOBL	·libc_ptrace_trampoline_addr(SB), RODATA, $8
DATA	·libc_ptrace_trampoline_addr+0(SB)/8, $libc_ptrace_trampoline<>(SB)

// --- mach_msg ---
TEXT libc_mach_msg_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mach_msg(SB)
GLOBL	·libc_mach_msg_trampoline_addr(SB), RODATA, $8
DATA	·libc_mach_msg_trampoline_addr+0(SB)/8, $libc_mach_msg_trampoline<>(SB)

// --- mach_reply_port ---
TEXT libc_mach_reply_port_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mach_reply_port(SB)
GLOBL	·libc_mach_reply_port_trampoline_addr(SB), RODATA, $8
DATA	·libc_mach_reply_port_trampoline_addr+0(SB)/8, $libc_mach_reply_port_trampoline<>(SB)
