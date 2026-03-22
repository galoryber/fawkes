package commands

import (
	"encoding/base64"
	"encoding/json"
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
		return errorResult("Error: no parameters provided")
	}

	var args base64Args
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Input == "" {
		return errorResult("Error: input is required")
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
		return errorf("Error: unknown action '%s' (use encode or decode)", args.Action)
	}
}

func base64Encode(args base64Args) structs.CommandResult {
	var data []byte

	if args.File {
		content, err := os.ReadFile(args.Input)
		if err != nil {
			return errorf("Error reading file: %v", err)
		}
		defer structs.ZeroBytes(content) // opsec: file may contain sensitive data
		data = content
	} else {
		data = []byte(args.Input)
	}

	encoded := base64.StdEncoding.EncodeToString(data)

	// Write to output file if specified
	if args.Output != "" {
		if err := os.WriteFile(args.Output, []byte(encoded), 0644); err != nil {
			return errorf("Error writing output file: %v", err)
		}
		return successf("[+] Encoded %d bytes → %d chars, written to %s", len(data), len(encoded), args.Output)
	}

	source := "string"
	if args.File {
		source = args.Input
	}
	return successf("[*] Encoded %d bytes from %s\n%s", len(data), source, encoded)
}

func base64Decode(args base64Args) structs.CommandResult {
	var encoded string

	if args.File {
		content, err := os.ReadFile(args.Input)
		if err != nil {
			return errorf("Error reading file: %v", err)
		}
		defer structs.ZeroBytes(content) // opsec: file may contain encoded secrets
		encoded = string(content)
	} else {
		encoded = args.Input
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return errorf("Error decoding base64: %v", err)
	}
	defer structs.ZeroBytes(decoded) // opsec: decoded data may be sensitive

	// Write to output file if specified
	if args.Output != "" {
		if err := os.WriteFile(args.Output, decoded, 0644); err != nil {
			return errorf("Error writing output file: %v", err)
		}
		return successf("[+] Decoded %d chars → %d bytes, written to %s", len(encoded), len(decoded), args.Output)
	}

	source := "string"
	if args.File {
		source = args.Input
	}
	return successf("[*] Decoded %d chars from %s → %d bytes\n%s", len(encoded), source, len(decoded), string(decoded))
}
