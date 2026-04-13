package commands

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// Base64Command implements data encoding/decoding: base64, xor, hex, rot13, url, caesar
type Base64Command struct{}

func (c *Base64Command) Name() string {
	return "base64"
}

func (c *Base64Command) Description() string {
	return "Data encoding toolkit — base64, XOR, hex, ROT13, URL, Caesar cipher"
}

type base64Args struct {
	Action string `json:"action"` // encode, decode, xor, hex, rot13, url, caesar
	Input  string `json:"input"`  // string to process, or file path if -file is set
	File   bool   `json:"file"`   // treat input as file path
	Output string `json:"output"` // optional output file path
	Key    string `json:"key"`    // XOR key (string or hex with 0x prefix)
	Shift  int    `json:"shift"`  // Caesar cipher shift value (1-25)
}

func (c *Base64Command) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[base64Args](task)
	if parseErr != nil {
		return *parseErr
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
	case "xor":
		return encodingXOR(args)
	case "hex":
		return encodingHex(args)
	case "hex-decode":
		return encodingHexDecode(args)
	case "rot13":
		return encodingROT13(args)
	case "url":
		return encodingURLEncode(args)
	case "url-decode":
		return encodingURLDecode(args)
	case "caesar":
		return encodingCaesar(args)
	default:
		return errorf("Error: unknown action '%s' (encode, decode, xor, hex, hex-decode, rot13, url, url-decode, caesar)", args.Action)
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

// readInputData reads input from string or file based on args.
func readInputData(args base64Args) ([]byte, error) {
	if args.File {
		data, err := os.ReadFile(args.Input)
		if err != nil {
			return nil, fmt.Errorf("reading file: %v", err)
		}
		return data, nil
	}
	return []byte(args.Input), nil
}

// writeOrReturn writes result to output file or returns it as string output.
func writeOrReturn(args base64Args, result []byte, actionName string, inputLen int) structs.CommandResult {
	if args.Output != "" {
		if err := os.WriteFile(args.Output, result, 0644); err != nil {
			return errorf("Error writing output file: %v", err)
		}
		return successf("[+] %s: %d bytes → %d bytes, written to %s", actionName, inputLen, len(result), args.Output)
	}
	source := "string"
	if args.File {
		source = args.Input
	}
	return successf("[*] %s %d bytes from %s\n%s", actionName, inputLen, source, string(result))
}

// parseXORKey parses a key string, supporting hex notation (0x prefix) or plain string.
func parseXORKey(key string) ([]byte, error) {
	if strings.HasPrefix(key, "0x") || strings.HasPrefix(key, "0X") {
		hexStr := strings.TrimPrefix(strings.TrimPrefix(key, "0x"), "0X")
		decoded, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, fmt.Errorf("invalid hex key: %v", err)
		}
		return decoded, nil
	}
	return []byte(key), nil
}

// encodingXOR applies XOR with a repeating key (symmetric: same operation for encode/decode).
func encodingXOR(args base64Args) structs.CommandResult {
	if args.Key == "" {
		return errorResult("Error: key is required for XOR (use -key 'secret' or -key 0x41424344)")
	}

	keyBytes, err := parseXORKey(args.Key)
	if err != nil {
		return errorf("Error: %v", err)
	}
	if len(keyBytes) == 0 {
		return errorResult("Error: XOR key must not be empty")
	}

	data, err := readInputData(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer structs.ZeroBytes(data)

	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ keyBytes[i%len(keyBytes)]
	}
	defer structs.ZeroBytes(result)

	// If output file specified, write raw bytes; otherwise hex-encode for display
	if args.Output != "" {
		if err := os.WriteFile(args.Output, result, 0644); err != nil {
			return errorf("Error writing output file: %v", err)
		}
		return successf("[+] XOR: %d bytes with %d-byte key, written to %s", len(data), len(keyBytes), args.Output)
	}

	hexOut := hex.EncodeToString(result)
	source := "string"
	if args.File {
		source = args.Input
	}
	return successf("[*] XOR %d bytes from %s (key: %d bytes)\n%s", len(data), source, len(keyBytes), hexOut)
}

// encodingHex hex-encodes the input data.
func encodingHex(args base64Args) structs.CommandResult {
	data, err := readInputData(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer structs.ZeroBytes(data)

	encoded := hex.EncodeToString(data)
	return writeOrReturn(args, []byte(encoded), "Hex encode", len(data))
}

// encodingHexDecode decodes hex-encoded input.
func encodingHexDecode(args base64Args) structs.CommandResult {
	data, err := readInputData(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer structs.ZeroBytes(data)

	// Strip whitespace and newlines from hex input
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, string(data))

	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return errorf("Error decoding hex: %v", err)
	}
	defer structs.ZeroBytes(decoded)

	return writeOrReturn(args, decoded, "Hex decode", len(data))
}

// encodingROT13 applies ROT13 (symmetric: same operation for encode/decode).
func encodingROT13(args base64Args) structs.CommandResult {
	data, err := readInputData(args)
	if err != nil {
		return errorf("Error: %v", err)
	}

	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = rot13Byte(b)
	}

	return writeOrReturn(args, result, "ROT13", len(data))
}

// rot13Byte applies ROT13 to a single byte, only transforming letters.
func rot13Byte(b byte) byte {
	switch {
	case b >= 'A' && b <= 'Z':
		return 'A' + (b-'A'+13)%26
	case b >= 'a' && b <= 'z':
		return 'a' + (b-'a'+13)%26
	default:
		return b
	}
}

// encodingURLEncode percent-encodes the input string.
func encodingURLEncode(args base64Args) structs.CommandResult {
	data, err := readInputData(args)
	if err != nil {
		return errorf("Error: %v", err)
	}

	encoded := url.QueryEscape(string(data))
	return writeOrReturn(args, []byte(encoded), "URL encode", len(data))
}

// encodingURLDecode decodes percent-encoded input.
func encodingURLDecode(args base64Args) structs.CommandResult {
	data, err := readInputData(args)
	if err != nil {
		return errorf("Error: %v", err)
	}

	decoded, err := url.QueryUnescape(string(data))
	if err != nil {
		return errorf("Error decoding URL: %v", err)
	}

	return writeOrReturn(args, []byte(decoded), "URL decode", len(data))
}

// encodingCaesar applies a Caesar cipher shift (1-25). Negative shift for decode.
func encodingCaesar(args base64Args) structs.CommandResult {
	if args.Shift == 0 {
		return errorResult("Error: shift is required for Caesar cipher (1-25, or negative to decode)")
	}

	// Normalize shift to 0-25 range
	shift := args.Shift % 26
	if shift < 0 {
		shift += 26
	}

	data, err := readInputData(args)
	if err != nil {
		return errorf("Error: %v", err)
	}

	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = caesarByte(b, shift)
	}

	return writeOrReturn(args, result, fmt.Sprintf("Caesar (shift %d)", args.Shift), len(data))
}

// caesarByte shifts a single byte by n positions, only transforming letters.
func caesarByte(b byte, shift int) byte {
	switch {
	case b >= 'A' && b <= 'Z':
		return byte('A' + (int(b-'A')+shift)%26)
	case b >= 'a' && b <= 'z':
		return byte('a' + (int(b-'a')+shift)%26)
	default:
		return b
	}
}
