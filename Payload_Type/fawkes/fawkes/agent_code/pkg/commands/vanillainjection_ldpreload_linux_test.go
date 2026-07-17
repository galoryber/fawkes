//go:build linux

package commands

import (
	"encoding/binary"
	"os"
	"syscall"
	"testing"
)

func TestBuildInitSO_ValidELF(t *testing.T) {
	shellcode := []byte{0xCC} // INT3
	so := buildInitSO(shellcode)

	if len(so) < 0x131 {
		t.Fatalf("SO too small: %d bytes", len(so))
	}

	// ELF magic
	if string(so[0:4]) != "\x7fELF" {
		t.Error("missing ELF magic")
	}

	// ELFCLASS64
	if so[4] != 2 {
		t.Errorf("class = %d, want 2 (ELFCLASS64)", so[4])
	}

	// ELFDATA2LSB
	if so[5] != 1 {
		t.Errorf("data = %d, want 1 (ELFDATA2LSB)", so[5])
	}

	// ET_DYN
	eType := binary.LittleEndian.Uint16(so[16:])
	if eType != 3 {
		t.Errorf("e_type = %d, want 3 (ET_DYN)", eType)
	}

	// e_machine
	eMachine := binary.LittleEndian.Uint16(so[18:])
	if eMachine != elfMachine() {
		t.Errorf("e_machine = 0x%X, want 0x%X", eMachine, elfMachine())
	}

	// 2 program headers
	phnum := binary.LittleEndian.Uint16(so[56:])
	if phnum != 2 {
		t.Errorf("e_phnum = %d, want 2", phnum)
	}

	// Shellcode at codeOff
	if so[0x130] != 0xCC {
		t.Errorf("shellcode byte = 0x%02X, want 0xCC", so[0x130])
	}
}

func TestBuildInitSO_DTInit(t *testing.T) {
	shellcode := []byte{0x90, 0x90} // NOP NOP
	so := buildInitSO(shellcode)

	// Dynamic section starts at 0x0B0
	// First entry should be DT_INIT (tag=12) with value=0x130 (codeOff)
	tag := binary.LittleEndian.Uint64(so[0x0B0:])
	val := binary.LittleEndian.Uint64(so[0x0B8:])
	if tag != 12 {
		t.Errorf("first dyn tag = %d, want 12 (DT_INIT)", tag)
	}
	if val != 0x130 {
		t.Errorf("DT_INIT value = 0x%X, want 0x130", val)
	}
}

func TestBuildInitSO_DTNull(t *testing.T) {
	so := buildInitSO([]byte{0xCC})

	// Last dynamic entry (6th, at offset 0x0B0 + 5*16 = 0x100) should be DT_NULL
	tag := binary.LittleEndian.Uint64(so[0x100:])
	val := binary.LittleEndian.Uint64(so[0x108:])
	if tag != 0 {
		t.Errorf("last dyn tag = %d, want 0 (DT_NULL)", tag)
	}
	if val != 0 {
		t.Errorf("DT_NULL value = %d, want 0", val)
	}
}

func TestBuildInitSO_LargeShellcode(t *testing.T) {
	sc := make([]byte, 8192)
	for i := range sc {
		sc[i] = byte(i & 0xFF)
	}
	so := buildInitSO(sc)

	if len(so) != 0x130+8192 {
		t.Errorf("size = %d, want %d", len(so), 0x130+8192)
	}

	// PT_LOAD filesz/memsz should cover the full file
	filesz := binary.LittleEndian.Uint64(so[0x40+32:])
	if filesz != uint64(len(so)) {
		t.Errorf("PT_LOAD filesz = %d, want %d", filesz, len(so))
	}

	// Shellcode preserved
	for i := 0; i < 256; i++ {
		if so[0x130+i] != byte(i&0xFF) {
			t.Errorf("shellcode byte %d = 0x%02X, want 0x%02X", i, so[0x130+i], byte(i&0xFF))
			break
		}
	}
}

func TestBuildInitSO_EmptyShellcode(t *testing.T) {
	so := buildInitSO(nil)
	if len(so) != 0x130 {
		t.Errorf("size = %d, want %d", len(so), 0x130)
	}
}

func TestMemfdCreate(t *testing.T) {
	fd, err := memfdCreate()
	if err != nil {
		t.Skipf("memfd_create not available: %v", err)
	}
	defer syscallClose(fd)

	// Write and read back
	data := []byte("test memfd data")
	n, _ := syscallWrite(fd, data)
	if n != len(data) {
		t.Errorf("wrote %d bytes, want %d", n, len(data))
	}
}

func syscallClose(fd int) {
	_ = syscall.Close(fd)
}

func syscallWrite(fd int, data []byte) (int, error) {
	f := os.NewFile(uintptr(fd), "memfd")
	n, err := f.Write(data)
	return n, err
}
