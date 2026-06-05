//go:build darwin && arm64

package commands

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestGenerateDarwinArm64SleepStub_Size(t *testing.T) {
	stub := generateDarwinArm64SleepStub()
	if len(stub) == 0 {
		t.Fatal("stub is empty")
	}
	// 35 instructions × 4 bytes = 140 bytes
	if len(stub) != 140 {
		t.Errorf("stub size = %d bytes, expected 140", len(stub))
	}
}

func TestGenerateDarwinArm64SleepStub_Deterministic(t *testing.T) {
	stub1 := generateDarwinArm64SleepStub()
	stub2 := generateDarwinArm64SleepStub()

	if len(stub1) != len(stub2) {
		t.Fatalf("non-deterministic length: %d vs %d", len(stub1), len(stub2))
	}
	for i := range stub1 {
		if stub1[i] != stub2[i] {
			t.Fatalf("non-deterministic at byte %d: 0x%02X vs 0x%02X", i, stub1[i], stub2[i])
		}
	}
}

func TestGenerateDarwinArm64SleepStub_InstructionAlignment(t *testing.T) {
	stub := generateDarwinArm64SleepStub()
	if len(stub)%4 != 0 {
		t.Errorf("stub size %d not 4-byte aligned (ARM64 requires 4-byte instruction alignment)", len(stub))
	}
}

func TestGenerateDarwinArm64SleepStub_Prologue(t *testing.T) {
	stub := generateDarwinArm64SleepStub()

	expected := []uint32{
		0xA9BF7BFD, // stp x29, x30, [sp, #-16]!
		0x910003FD, // mov x29, sp
		0xA9BF53F3, // stp x19, x20, [sp, #-16]!
		0xAA0003F3, // mov x19, x0
	}

	for i, exp := range expected {
		got := binary.LittleEndian.Uint32(stub[i*4:])
		if got != exp {
			t.Errorf("instruction %d: got 0x%08X, want 0x%08X", i, got, exp)
		}
	}
}

func TestGenerateDarwinArm64SleepStub_Epilogue(t *testing.T) {
	stub := generateDarwinArm64SleepStub()
	numInsns := len(stub) / 4

	expected := []uint32{
		0xA8C153F3, // ldp x19, x20, [sp], #16
		0xA8C17BFD, // ldp x29, x30, [sp], #16
		0xD2800000, // mov x0, #0
		0xD65F03C0, // ret
	}

	for i, exp := range expected {
		idx := numInsns - len(expected) + i
		got := binary.LittleEndian.Uint32(stub[idx*4:])
		if got != exp {
			t.Errorf("epilogue instruction %d (index %d): got 0x%08X, want 0x%08X", i, idx, got, exp)
		}
	}
}

func TestGenerateDarwinArm64SleepStub_SvcCount(t *testing.T) {
	stub := generateDarwinArm64SleepStub()
	numInsns := len(stub) / 4

	svcCount := 0
	for i := 0; i < numInsns; i++ {
		insn := binary.LittleEndian.Uint32(stub[i*4:])
		if insn == 0xD4001001 {
			svcCount++
		}
	}

	// ulock_wait, nanosleep, ulock_wake = 3 svc instructions
	if svcCount != 3 {
		t.Errorf("found %d svc #0x80 instructions, expected 3", svcCount)
	}
}

func TestGenerateDarwinArm64SleepStub_SyscallNumbers(t *testing.T) {
	stub := generateDarwinArm64SleepStub()
	numInsns := len(stub) / 4

	expected := map[uint32]string{
		515: "SYS___ulock_wait",
		516: "SYS___ulock_wake",
		240: "SYS_nanosleep",
	}

	for num, name := range expected {
		// MOVZ X16, #num encodes as 0xD2800000 | (num << 5) | 16
		target := uint32(0xD2800000) | (num << 5) | 16
		found := false
		for i := 0; i < numInsns; i++ {
			insn := binary.LittleEndian.Uint32(stub[i*4:])
			if insn == target {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("syscall number %d (%s) not found as MOVZ X16 instruction", num, name)
		}
	}
}

func TestDarwinDataBlockLayout(t *testing.T) {
	if darDataOffState != 0 {
		t.Error("state must be at offset 0 for ulock_wait compare")
	}
	if darDataOffTvSec%8 != 0 {
		t.Error("tv_sec must be 8-byte aligned")
	}
	if darDataOffTvNsec%8 != 0 {
		t.Error("tv_nsec must be 8-byte aligned")
	}
	if darDataBlockSize != 48 {
		t.Errorf("data block size = %d, expected 48", darDataBlockSize)
	}
}

func TestStackSpoofInit_Lifecycle_Darwin(t *testing.T) {
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

func TestStackSpoofSleep_MultipleCycles_Darwin(t *testing.T) {
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

func TestStackSpoofSleep_FallbackWhenNotInit_Darwin(t *testing.T) {
	start := time.Now()
	StackSpoofSleep(50 * time.Millisecond)
	elapsed := time.Since(start)

	if elapsed < 30*time.Millisecond {
		t.Errorf("fallback sleep too short: %v", elapsed)
	}
}
