// Assembly trampolines for macOS ARM64 stack spoof sleep thread.
// These jump to libSystem symbols resolved by the dynamic linker.

#include "textflag.h"

// --- pthread_create ---
TEXT libc_pthread_create_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_pthread_create(SB)
GLOBL	·libc_pthread_create_trampoline_addr(SB), RODATA, $8
DATA	·libc_pthread_create_trampoline_addr+0(SB)/8, $libc_pthread_create_trampoline<>(SB)

// --- __ulock_wake ---
TEXT libc___ulock_wake_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc___ulock_wake(SB)
GLOBL	·libc___ulock_wake_trampoline_addr(SB), RODATA, $8
DATA	·libc___ulock_wake_trampoline_addr+0(SB)/8, $libc___ulock_wake_trampoline<>(SB)
