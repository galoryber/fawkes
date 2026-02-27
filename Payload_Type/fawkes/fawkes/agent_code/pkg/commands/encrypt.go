package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type EncryptCommand struct{}

func (c *EncryptCommand) Name() string { return "encrypt" }
func (c *EncryptCommand) Description() string {
	return "Encrypt or decrypt files using AES-256-GCM for secure data staging"
}

type encryptArgs struct {
	Action string `json:"action"` // encrypt, decrypt
	Path   string `json:"path"`   // input file path
	Output string `json:"output"` // output file path (optional)
	Key    string `json:"key"`    // base64-encoded key (auto-generated for encrypt if empty)
}

const (
	encryptMaxFileSize = 500 * 1024 * 1024 // 500MB
	aes256KeySize      = 32                 // 256 bits
)

func (c *EncryptCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (action, path). Actions: encrypt, decrypt",
			Status:    "error",
			Completed: true,
		}
	}

	var args encryptArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: path is required",
			Status:    "error",
			Completed: true,
		}
	}

	if abs, err := filepath.Abs(args.Path); err == nil {
		args.Path = abs
	}

	switch args.Action {
	case "encrypt":
		return encryptFile(args)
	case "decrypt":
		return decryptFile(args)
	default:
		return structs.CommandResult{
			Output:    "Error: action must be 'encrypt' or 'decrypt'",
			Status:    "error",
			Completed: true,
		}
	}
}

func encryptFile(args encryptArgs) structs.CommandResult {
	// Read input file
	info, err := os.Stat(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	if info.Size() > encryptMaxFileSize {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: file too large (%d bytes, max %d)", info.Size(), encryptMaxFileSize),
			Status:    "error",
			Completed: true,
		}
	}

	plaintext, err := os.ReadFile(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Get or generate key
	var key []byte
	if args.Key != "" {
		key, err = base64.StdEncoding.DecodeString(args.Key)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error decoding key: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		if len(key) != aes256KeySize {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: key must be %d bytes (got %d)", aes256KeySize, len(key)),
				Status:    "error",
				Completed: true,
			}
		}
	} else {
		key = make([]byte, aes256KeySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error generating key: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating cipher: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating GCM: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error generating nonce: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Output format: nonce + ciphertext (GCM tag appended by Seal)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Determine output path
	outPath := args.Output
	if outPath == "" {
		outPath = args.Path + ".enc"
	}
	if abs, err := filepath.Abs(outPath); err == nil {
		outPath = abs
	}

	if err := os.WriteFile(outPath, ciphertext, 0600); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing encrypted file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Encrypted: %s → %s\n", args.Path, outPath))
	sb.WriteString(fmt.Sprintf("Algorithm: AES-256-GCM\n"))
	sb.WriteString(fmt.Sprintf("Key (base64): %s\n", base64.StdEncoding.EncodeToString(key)))
	sb.WriteString(fmt.Sprintf("Input size:  %d bytes\n", len(plaintext)))
	sb.WriteString(fmt.Sprintf("Output size: %d bytes\n", len(ciphertext)))
	sb.WriteString("\n⚠ Save the key — it is required for decryption")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "completed",
		Completed: true,
	}
}

func decryptFile(args encryptArgs) structs.CommandResult {
	if args.Key == "" {
		return structs.CommandResult{
			Output:    "Error: key is required for decryption (base64-encoded AES-256 key)",
			Status:    "error",
			Completed: true,
		}
	}

	key, err := base64.StdEncoding.DecodeString(args.Key)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding key: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	if len(key) != aes256KeySize {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: key must be %d bytes (got %d)", aes256KeySize, len(key)),
			Status:    "error",
			Completed: true,
		}
	}

	// Read encrypted file
	ciphertext, err := os.ReadFile(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating cipher: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating GCM: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return structs.CommandResult{
			Output:    "Error: encrypted file too small (corrupted?)",
			Status:    "error",
			Completed: true,
		}
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decrypting: %v (wrong key or corrupted file)", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Determine output path
	outPath := args.Output
	if outPath == "" {
		outPath = strings.TrimSuffix(args.Path, ".enc")
		if outPath == args.Path {
			outPath = args.Path + ".dec"
		}
	}
	if abs, err := filepath.Abs(outPath); err == nil {
		outPath = abs
	}

	if err := os.WriteFile(outPath, plaintext, 0600); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing decrypted file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Decrypted: %s → %s\n", args.Path, outPath))
	sb.WriteString(fmt.Sprintf("Input size:  %d bytes\n", len(ciphertext)+nonceSize))
	sb.WriteString(fmt.Sprintf("Output size: %d bytes\n", len(plaintext)))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "completed",
		Completed: true,
	}
}
