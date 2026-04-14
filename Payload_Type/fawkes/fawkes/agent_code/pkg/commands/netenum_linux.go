//go:build linux
// +build linux

package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

const neAllActionsUnix = "users, groups, groupmembers, admins, sessions, shares"

func (c *NetEnumCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[netEnumArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	remoteTimeout := 30 * time.Second
	if args.Timeout > 0 {
		remoteTimeout = time.Duration(args.Timeout) * time.Second
	}
	_ = remoteTimeout // reserved for future remote ops

	switch strings.ToLower(args.Action) {
	case "users":
		return neLinuxUsers()
	case "groups", "localgroups":
		return neLinuxGroups()
	case "groupmembers":
		group := args.Group
		if group == "" {
			group = args.Target
		}
		if group == "" {
			return errorf("groupmembers requires -group parameter")
		}
		return neLinuxGroupMembers(group)
	case "admins":
		return neLinuxAdmins()
	case "sessions", "loggedon":
		return neLinuxSessions()
	case "shares":
		return neLinuxShares()
	case "domainusers", "domaingroups", "domaininfo", "mapped":
		return errorf("%s is not available on Linux", args.Action)
	default:
		return errorf("Unknown action: %s\nAvailable: %s", args.Action, neAllActionsUnix)
	}
}

// neLinuxUsers enumerates users from /etc/passwd, filtering system accounts.
func neLinuxUsers() structs.CommandResult {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return errorf("Failed to read /etc/passwd: %v", err)
	}
	defer f.Close()

	var entries []netEnumEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		userType := "local_user"
		if uid < 1000 && uid != 0 {
			userType = "system_user"
		}
		entries = append(entries, netEnumEntry{
			Name:    parts[0],
			Comment: parts[4], // GECOS field
			Type:    userType,
			UID:     uid,
			GID:     gid,
			Home:    parts[5],
			Shell:   parts[6],
		})
	}

	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// neLinuxGroups enumerates groups from /etc/group.
func neLinuxGroups() structs.CommandResult {
	f, err := os.Open("/etc/group")
	if err != nil {
		return errorf("Failed to read /etc/group: %v", err)
	}
	defer f.Close()

	var entries []netEnumEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		gid, _ := strconv.Atoi(parts[2])
		members := parts[3]
		memberCount := 0
		if members != "" {
			memberCount = len(strings.Split(members, ","))
		}
		entries = append(entries, netEnumEntry{
			Name:    parts[0],
			Type:    "local_group",
			GID:     gid,
			Comment: fmt.Sprintf("%d members", memberCount),
		})
	}

	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// neLinuxGroupMembers returns members of a specific group from /etc/group.
func neLinuxGroupMembers(group string) structs.CommandResult {
	f, err := os.Open("/etc/group")
	if err != nil {
		return errorf("Failed to read /etc/group: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		if parts[0] != group {
			continue
		}
		gid, _ := strconv.Atoi(parts[2])
		var entries []netEnumEntry
		// Members listed in the group file
		if parts[3] != "" {
			for _, member := range strings.Split(parts[3], ",") {
				member = strings.TrimSpace(member)
				if member != "" {
					entries = append(entries, netEnumEntry{
						Name:   member,
						Type:   "group_member",
						Source: group,
						GID:    gid,
					})
				}
			}
		}
		// Also check /etc/passwd for users with this as primary GID
		if pwf, err := os.Open("/etc/passwd"); err == nil {
			defer pwf.Close()
			pwScanner := bufio.NewScanner(pwf)
			for pwScanner.Scan() {
				pwParts := strings.Split(pwScanner.Text(), ":")
				if len(pwParts) < 4 {
					continue
				}
				primaryGID, _ := strconv.Atoi(pwParts[3])
				if primaryGID == gid {
					// Check if already in the member list
					alreadyListed := false
					for _, e := range entries {
						if e.Name == pwParts[0] {
							alreadyListed = true
							break
						}
					}
					if !alreadyListed {
						entries = append(entries, netEnumEntry{
							Name:    pwParts[0],
							Type:    "group_member",
							Source:  group,
							GID:     gid,
							Comment: "primary group",
						})
					}
				}
			}
		}
		data, _ := json.Marshal(entries)
	return successResult(string(data))
	}

	return errorf("Group not found: %s", group)
}

// neLinuxAdmins returns members of root, sudo, and wheel groups.
func neLinuxAdmins() structs.CommandResult {
	adminGroups := []string{"root", "sudo", "wheel", "admin"}
	var entries []netEnumEntry

	f, err := os.Open("/etc/group")
	if err != nil {
		return errorf("Failed to read /etc/group: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 4 {
			continue
		}
		isAdmin := false
		for _, ag := range adminGroups {
			if parts[0] == ag {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			continue
		}
		if parts[3] == "" {
			continue
		}
		for _, member := range strings.Split(parts[3], ",") {
			member = strings.TrimSpace(member)
			if member != "" {
				entries = append(entries, netEnumEntry{
					Name:   member,
					Type:   "admin",
					Source: parts[0],
				})
			}
		}
	}

	// Always include root
	entries = append(entries, netEnumEntry{
		Name:   "root",
		Type:   "admin",
		Source: "uid=0",
	})

	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// neLinuxSessions parses /var/run/utmp or falls back to who output.
func neLinuxSessions() structs.CommandResult {
	// Try reading utmp directly
	entries, err := parseUtmp("/var/run/utmp")
	if err != nil {
		// Fallback: parse /etc/passwd login shells as "potential users"
		return errorf("Failed to read utmp: %v", err)
	}
	data, _ := json.Marshal(entries)
	return successResult(string(data))
}

// parseUtmp reads Linux utmp file to get logged-in users.
func parseUtmp(path string) ([]netEnumEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Linux utmp record is 384 bytes on x86_64
	const utmpSize = 384
	const utTypeUser = 7 // USER_PROCESS

	var entries []netEnumEntry
	buf := make([]byte, utmpSize)
	for {
		n, err := f.Read(buf)
		if n < utmpSize || err != nil {
			break
		}
		utType := int32(buf[0]) | int32(buf[1])<<8 | int32(buf[2])<<16 | int32(buf[3])<<24
		if utType != utTypeUser {
			continue
		}
		user := strings.TrimRight(string(buf[8:40]), "\x00")
		line := strings.TrimRight(string(buf[40:72]), "\x00")
		host := strings.TrimRight(string(buf[76:332]), "\x00")
		if user == "" {
			continue
		}
		entries = append(entries, netEnumEntry{
			Name:   user,
			Type:   "loggedon",
			Source: line,
			Client: host,
		})
	}
	return entries, nil
}

// neLinuxShares enumerates NFS exports and Samba shares.
func neLinuxShares() structs.CommandResult {
	var entries []netEnumEntry

	// NFS exports from /etc/exports
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
			comment := ""
			if len(parts) > 1 {
				comment = strings.Join(parts[1:], " ")
			}
			entries = append(entries, netEnumEntry{
				Name:    parts[0],
				Type:    "nfs_export",
				Comment: comment,
			})
		}
		f.Close()
	}

	// Samba shares from /etc/samba/smb.conf
	if f, err := os.Open("/etc/samba/smb.conf"); err == nil {
		scanner := bufio.NewScanner(f)
		var currentShare string
		var currentPath string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				if currentShare != "" && currentShare != "global" {
					entries = append(entries, netEnumEntry{
						Name: currentShare,
						Type: "smb_share",
						Path: currentPath,
					})
				}
				currentShare = strings.Trim(line, "[]")
				currentPath = ""
			} else if strings.HasPrefix(strings.ToLower(line), "path") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					currentPath = strings.TrimSpace(parts[1])
				}
			}
		}
		if currentShare != "" && currentShare != "global" {
			entries = append(entries, netEnumEntry{
				Name: currentShare,
				Type: "smb_share",
				Path: currentPath,
			})
		}
		f.Close()
	}

	if len(entries) == 0 {
		noShares := []netEnumEntry{{Name: "(none)", Type: "info", Comment: "No NFS exports or Samba shares found"}}
		data, _ := json.Marshal(noShares)
		return successResult(string(data))
	}

	data, _ := json.Marshal(entries)
	return successResult(string(data))
}
