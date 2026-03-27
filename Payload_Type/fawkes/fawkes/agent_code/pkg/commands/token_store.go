//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

type TokenStoreCommand struct{}

func (c *TokenStoreCommand) Name() string { return "token-store" }
func (c *TokenStoreCommand) Description() string {
	return "Save, list, restore, and remove named tokens"
}

type tokenStoreArgs struct {
	Action string `json:"action"` // save, list, use, remove
	Name   string `json:"name"`   // token label
}

func (c *TokenStoreCommand) Execute(task structs.Task) structs.CommandResult {
	var args tokenStoreArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch args.Action {
	case "save":
		return tokenStoreSave(args.Name)
	case "list":
		return tokenStoreList()
	case "use":
		return tokenStoreUse(args.Name)
	case "remove":
		return tokenStoreRemove(args.Name)
	default:
		return errorf("Unknown action: %s (use save, list, use, remove)", args.Action)
	}
}

func tokenStoreSave(name string) structs.CommandResult {
	if name == "" {
		return errorResult("Error: name is required for save action\nUsage: token-store -action save -name \"admin\"")
	}

	// Determine the source of the current token
	source := "unknown"
	if HasActiveImpersonation() {
		if GetIdentityCredentials() != nil {
			source = "make-token"
		} else {
			source = "steal-token"
		}
	}

	if err := SaveTokenToStore(name, source); err != nil {
		return errorf("Error saving token: %v", err)
	}

	identity, _ := GetCurrentIdentity()
	return successf("Saved current token as %q (%s)", name, identity)
}

func tokenStoreList() structs.CommandResult {
	store := ListTokenStore()
	if len(store) == 0 {
		return successResult("Token store is empty. Use steal-token or make-token, then token-store -action save -name <label>")
	}

	// Sort names for consistent output
	names := make([]string, 0, len(store))
	for name := range store {
		names = append(names, name)
	}
	sort.Strings(names)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Token Store — %d saved\n\n", len(store)))
	sb.WriteString(fmt.Sprintf("%-20s %-35s %s\n", "NAME", "IDENTITY", "SOURCE"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	for _, name := range names {
		entry := store[name]
		identity := entry.Identity
		if identity == "" {
			identity = "(unknown)"
		}
		hasCreds := ""
		if entry.Creds != nil {
			hasCreds = " [creds]"
		}
		sb.WriteString(fmt.Sprintf("%-20s %-35s %s%s\n",
			truncStr(name, 20),
			truncStr(identity, 35),
			entry.Source,
			hasCreds))
	}

	// Show current active token
	sb.WriteString("\n")
	if HasActiveImpersonation() {
		current, _ := GetCurrentIdentity()
		sb.WriteString(fmt.Sprintf("Active: %s", current))
	} else {
		sb.WriteString("Active: (process token — no impersonation)")
	}

	return successResult(sb.String())
}

func tokenStoreUse(name string) structs.CommandResult {
	if name == "" {
		return errorResult("Error: name is required for use action\nUsage: token-store -action use -name \"admin\"")
	}

	oldIdentity := "(process token)"
	if HasActiveImpersonation() {
		oldIdentity, _ = GetCurrentIdentity()
	}

	identity, err := UseTokenFromStore(name)
	if err != nil {
		return errorf("Error restoring token %q: %v", name, err)
	}

	return successf("Switched to token %q\nOld: %s\nNew: %s", name, oldIdentity, identity)
}

func tokenStoreRemove(name string) structs.CommandResult {
	if name == "" {
		return errorResult("Error: name is required for remove action\nUsage: token-store -action remove -name \"admin\"")
	}

	if err := RemoveTokenFromStore(name); err != nil {
		return errorf("Error: %v", err)
	}

	return successf("Removed token %q from store", name)
}
