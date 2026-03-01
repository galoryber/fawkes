package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"fawkes/pkg/structs"
)

// Base64Command implements the base64 command for encoding/decoding
type Base64Command struct{}

func (c *Base64Command) Name() string {
	return "base64"
}

func (c *Base64Command) Description() string {
	return "Encode or decode base64 — files and strings, no subprocess spawned"
}

type base64Args struct {
	Action string `json:"action"` // encode, decode
	Input  string `json:"input"`  // string to encode/decode, or file path if -file is set
	File   bool   `json:"file"`   // treat input as file path
	Output string `json:"output"` // optional output file path
}

func (c *Base64Command) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: no parameters provided",
			Status:    "error",
			Completed: true,
		}
	}

	var args base64Args
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Input == "" {
		return structs.CommandResult{
			Output:    "Error: input is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		args.Action = "encode"
	}

	switch args.Action {
	case "encode":
		return base64Encode(args)
	case "decode":
		return base64Decode(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown action '%s' (use encode or decode)", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func base64Encode(args base64Args) structs.CommandResult {
	var data []byte

	if args.File {
		content, err := os.ReadFile(args.Input)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error reading file: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		data = content
	} else {
		data = []byte(args.Input)
	}

	encoded := base64.StdEncoding.EncodeToString(data)

	// Write to output file if specified
	if args.Output != "" {
		if err := os.WriteFile(args.Output, []byte(encoded), 0644); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error writing output file: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] Encoded %d bytes → %d chars, written to %s", len(data), len(encoded), args.Output),
			Status:    "success",
			Completed: true,
		}
	}

	source := "string"
	if args.File {
		source = args.Input
	}
	return structs.CommandResult{
		Output:    fmt.Sprintf("[*] Encoded %d bytes from %s\n%s", len(data), source, encoded),
		Status:    "success",
		Completed: true,
	}
}

func base64Decode(args base64Args) structs.CommandResult {
	var encoded string

	if args.File {
		content, err := os.ReadFile(args.Input)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error reading file: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		encoded = string(content)
	} else {
		encoded = args.Input
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding base64: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Write to output file if specified
	if args.Output != "" {
		if err := os.WriteFile(args.Output, decoded, 0644); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error writing output file: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] Decoded %d chars → %d bytes, written to %s", len(encoded), len(decoded), args.Output),
			Status:    "success",
			Completed: true,
		}
	}

	source := "string"
	if args.File {
		source = args.Input
	}
	return structs.CommandResult{
		Output:    fmt.Sprintf("[*] Decoded %d chars from %s → %d bytes\n%s", len(encoded), source, len(decoded), string(decoded)),
		Status:    "success",
		Completed: true,
	}
}
