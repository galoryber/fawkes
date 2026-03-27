//go:build linux

package commands

import (
	"bufio"
	"bytes"
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
		return linuxUserAdd(args)
	case "delete":
		return linuxUserDelete(args)
	case "info":
		return linuxUserInfo(args)
	case "password":
		return linuxUserPassword(args)
	case "group-add":
		return linuxUserGroupAdd(args)
	case "group-remove":
		return linuxUserGroupRemove(args)
	default:
		return errorf("Unknown action: %s\nAvailable: add, delete, info, password, group-add, group-remove", args.Action)
	}
}

func linuxUserAdd(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for add action")
	}
	if args.Password == "" {
		return errorResult("Error: password is required for add action")
	}

	// Build useradd command
	cmdArgs := []string{"-m"} // create home directory
	if args.Comment != "" {
		cmdArgs = append(cmdArgs, "-c", args.Comment)
	}
	cmdArgs = append(cmdArgs, "-s", "/bin/bash", args.Username)

	out, err := execCmdTimeout("useradd", cmdArgs...)
	if err != nil {
		return errorf("Error creating user '%s': %v\n%s", args.Username, err, string(out))
	}

	// Set password via chpasswd (reads username:password from stdin)
	cmd, cancel := execCmdCtx("chpasswd")
	defer cancel()
	// opsec: build stdin as byte slice so we can zero it after use
	stdinBuf := []byte(args.Username + ":" + args.Password)
	defer structs.ZeroBytes(stdinBuf)
	cmd.Stdin = bytes.NewReader(stdinBuf)
	passOut, passErr := cmd.CombinedOutput()
	if passErr != nil {
		return errorf("User '%s' created but password set failed: %v\n%s", args.Username, passErr, string(passOut))
	}

	return successf("Successfully created user '%s'", args.Username)
}

func linuxUserDelete(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for delete action")
	}

	out, err := execCmdTimeout("userdel", "-r", args.Username)
	if err != nil {
		return errorf("Error deleting user '%s': %v\n%s", args.Username, err, string(out))
	}

	return successf("Successfully deleted user '%s' (home directory removed)", args.Username)
}

func linuxUserInfo(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for info action")
	}

	var sb strings.Builder

	// Parse /etc/passwd for basic info
	passwdEntry, err := findPasswdEntry(args.Username)
	if err != nil {
		return errorf("User '%s' not found: %v", args.Username, err)
	}

	fields := strings.SplitN(passwdEntry, ":", 7)
	if len(fields) < 7 {
		return errorf("Invalid passwd entry for '%s'", args.Username)
	}

	sb.WriteString(fmt.Sprintf("User:    %s\n", fields[0]))
	sb.WriteString(fmt.Sprintf("UID:     %s\n", fields[2]))
	sb.WriteString(fmt.Sprintf("GID:     %s\n", fields[3]))
	if fields[4] != "" {
		sb.WriteString(fmt.Sprintf("Comment: %s\n", fields[4]))
	}
	sb.WriteString(fmt.Sprintf("Home:    %s\n", fields[5]))
	sb.WriteString(fmt.Sprintf("Shell:   %s\n", fields[6]))

	// Check if user can login (shell != /usr/sbin/nologin, /bin/false)
	shell := fields[6]
	if shell == "/usr/sbin/nologin" || shell == "/bin/false" || shell == "/sbin/nologin" {
		sb.WriteString("Login:   Disabled\n")
	} else {
		sb.WriteString("Login:   Enabled\n")
	}

	// Try to read shadow file for password aging info
	if shadowEntry, err := findShadowEntry(args.Username); err == nil {
		sFields := strings.Split(shadowEntry, ":")
		if len(sFields) >= 9 {
			// Password field
			switch {
			case sFields[1] == "!" || sFields[1] == "*" || sFields[1] == "!!":
				sb.WriteString("Password: Locked\n")
			case sFields[1] == "":
				sb.WriteString("Password: Empty (no password)\n")
			default:
				sb.WriteString("Password: Set\n")
			}
			if sFields[2] != "" && sFields[2] != "0" {
				sb.WriteString(fmt.Sprintf("Last Changed: day %s\n", sFields[2]))
			}
			if sFields[4] != "" && sFields[4] != "99999" {
				sb.WriteString(fmt.Sprintf("Max Age: %s days\n", sFields[4]))
			}
			if sFields[6] != "" {
				sb.WriteString(fmt.Sprintf("Inactive: %s days\n", sFields[6]))
			}
			if sFields[7] != "" {
				sb.WriteString(fmt.Sprintf("Expires: day %s\n", sFields[7]))
			}
		}
	}

	// Get group membership natively from /etc/group (no subprocess spawned)
	groups := findUserGroups(args.Username, fields[3])
	if len(groups) > 0 {
		sb.WriteString(fmt.Sprintf("Groups:  %s", strings.Join(groups, ", ")))

		// Check sudo access
		for _, g := range groups {
			gl := strings.ToLower(g)
			if gl == "sudo" || gl == "wheel" || gl == "root" {
				sb.WriteString("\nPrivilege: Sudo/Admin access")
				break
			}
		}
	}

	return successResult(sb.String())
}

func linuxUserPassword(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for password action")
	}
	if args.Password == "" {
		return errorResult("Error: password is required for password action")
	}

	cmd, cancel := execCmdCtx("chpasswd")
	defer cancel()
	// opsec: build stdin as byte slice so we can zero it after use
	stdinBuf := []byte(args.Username + ":" + args.Password)
	defer structs.ZeroBytes(stdinBuf)
	cmd.Stdin = bytes.NewReader(stdinBuf)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Error setting password for '%s': %v\n%s", args.Username, err, string(out))
	}

	return successf("Successfully changed password for '%s'", args.Username)
}

func linuxUserGroupAdd(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for group-add action")
	}
	if args.Group == "" {
		return errorResult("Error: group is required for group-add action")
	}

	out, err := execCmdTimeout("usermod", "-aG", args.Group, args.Username)
	if err != nil {
		return errorf("Error adding '%s' to group '%s': %v\n%s", args.Username, args.Group, err, string(out))
	}

	return successf("Successfully added '%s' to group '%s'", args.Username, args.Group)
}

func linuxUserGroupRemove(args netUserArgs) structs.CommandResult {
	if args.Username == "" {
		return errorResult("Error: username is required for group-remove action")
	}
	if args.Group == "" {
		return errorResult("Error: group is required for group-remove action")
	}

	out, err := execCmdTimeout("gpasswd", "-d", args.Username, args.Group)
	if err != nil {
		return errorf("Error removing '%s' from group '%s': %v\n%s", args.Username, args.Group, err, string(out))
	}

	return successf("Successfully removed '%s' from group '%s'", args.Username, args.Group)
}

// findUserGroups returns all group names a user belongs to by parsing /etc/group natively.
// primaryGID is the user's primary group ID from /etc/passwd (used to include the primary group).
// No subprocess spawned — opsec safe.
func findUserGroups(username, primaryGID string) []string {
	var groups []string
	seen := make(map[string]bool)

	f, err := os.Open("/etc/group")
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: group_name:password:GID:user_list
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 4 {
			continue
		}
		groupName := fields[0]
		gid := fields[2]
		members := fields[3]

		// Include if this is the user's primary group (by GID match)
		if gid == primaryGID && !seen[groupName] {
			groups = append(groups, groupName)
			seen[groupName] = true
		}

		// Include if user is in the member list
		for _, member := range strings.Split(members, ",") {
			if strings.TrimSpace(member) == username {
				if !seen[groupName] {
					groups = append(groups, groupName)
					seen[groupName] = true
				}
				break
			}
		}
	}

	return groups
}

// findPasswdEntry searches /etc/passwd for a username and returns the matching line.
func findPasswdEntry(username string) (string, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return "", err
	}
	defer f.Close()

	prefix := username + ":"
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, prefix) {
			return line, nil
		}
	}
	return "", fmt.Errorf("user not found")
}

// findShadowEntry searches /etc/shadow for a username. Requires root.
func findShadowEntry(username string) (string, error) {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return "", err
	}
	defer f.Close()

	prefix := username + ":"
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, prefix) {
			return line, nil
		}
	}
	return "", fmt.Errorf("user not found in shadow")
}
