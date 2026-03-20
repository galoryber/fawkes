//go:build !windows

package commands

import "strings"

// credShadowEntry represents a parsed /etc/shadow entry with an active hash.
type credShadowEntry struct {
	User string
	Hash string
}

// parseShadowLines parses /etc/shadow format lines and returns entries with active
// password hashes. Locked/disabled accounts (hash is "*", empty, or starts with "!")
// are skipped. If userFilter is non-empty, only matching usernames are returned
// (case-insensitive substring match).
func parseShadowLines(lines []string, userFilter string) []credShadowEntry {
	var entries []credShadowEntry
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}
		user := parts[0]
		hash := parts[1]

		if userFilter != "" && !strings.Contains(strings.ToLower(user), strings.ToLower(userFilter)) {
			continue
		}

		// Skip locked/disabled accounts
		if hash == "*" || hash == "" || strings.HasPrefix(hash, "!") {
			continue
		}

		entries = append(entries, credShadowEntry{User: user, Hash: hash})
	}
	return entries
}

// credPasswdEntry represents a parsed /etc/passwd entry for an account with a login shell.
type credPasswdEntry struct {
	User       string
	UID        string
	GID        string
	Home       string
	Shell      string
	PasswdHash string // non-empty if password hash is in passwd (legacy, rare)
}

// parsePasswdLines parses /etc/passwd format lines and returns entries for accounts
// with login shells (filters out nologin/false shells). If userFilter is non-empty,
// only matching usernames are returned (case-insensitive substring match).
func parsePasswdLines(lines []string, userFilter string) []credPasswdEntry {
	var entries []credPasswdEntry
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		user := parts[0]
		shell := parts[6]

		if userFilter != "" && !strings.Contains(strings.ToLower(user), strings.ToLower(userFilter)) {
			continue
		}

		if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") || shell == "/usr/sbin/nologin" || shell == "/bin/false" {
			continue
		}

		entry := credPasswdEntry{
			User:  user,
			UID:   parts[2],
			GID:   parts[3],
			Home:  parts[5],
			Shell: shell,
		}
		if parts[1] != "x" && parts[1] != "*" && parts[1] != "" {
			entry.PasswdHash = parts[1]
		}

		entries = append(entries, entry)
	}
	return entries
}

// credGshadowEntry represents a parsed /etc/gshadow entry with a group password.
type credGshadowEntry struct {
	Line string
}

// parseGshadowLines parses /etc/gshadow format lines and returns entries that have
// group passwords set (filters out empty, "!", and "*" password fields).
func parseGshadowLines(lines []string) []credGshadowEntry {
	var entries []credGshadowEntry
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 || parts[1] == "" || parts[1] == "!" || parts[1] == "*" {
			continue
		}
		entries = append(entries, credGshadowEntry{Line: line})
	}
	return entries
}
