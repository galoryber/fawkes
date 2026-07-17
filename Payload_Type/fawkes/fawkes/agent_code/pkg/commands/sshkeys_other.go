//go:build !windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sshKeysEnumerateWindows is a no-op on non-Windows platforms.
func sshKeysEnumerateWindows() string {
	return ""
}

// sshKeysEnumerateUnix returns Unix-specific SSH enumeration:
// - SSH agent sockets (SSH_AUTH_SOCK + /tmp/ssh-*/agent.*)
// - authorized_keys across all accessible user home directories
func sshKeysEnumerateUnix() string {
	var sb strings.Builder

	// --- SSH Agent Sockets ---
	var sockets []string
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if info, err := os.Stat(sock); err == nil && info.Mode().Type() == os.ModeSocket {
			sockets = append(sockets, fmt.Sprintf("  %s (SSH_AUTH_SOCK, current user)", sock))
		}
	}
	matches, _ := filepath.Glob("/tmp/ssh-*/agent.*")
	for _, m := range matches {
		if info, err := os.Stat(m); err == nil && info.Mode().Type() == os.ModeSocket {
			already := false
			for _, s := range sockets {
				if strings.Contains(s, m) {
					already = true
					break
				}
			}
			if !already {
				sockets = append(sockets, fmt.Sprintf("  %s", m))
			}
		}
	}

	if len(sockets) > 0 {
		sb.WriteString(fmt.Sprintf("\n[SSH Agent Sockets] %d found:\n", len(sockets)))
		for _, s := range sockets {
			sb.WriteString(s + "\n")
		}
	} else {
		sb.WriteString("\n[SSH Agent Sockets] None found\n")
	}

	// --- Authorized Keys Across Users ---
	type authKeyEntry struct {
		user    string
		path    string
		count   int
		hasFrom bool
	}
	var entries []authKeyEntry

	homeDirs := []string{"/root"}
	if homes, err := filepath.Glob("/home/*"); err == nil {
		homeDirs = append(homeDirs, homes...)
	}

	for _, home := range homeDirs {
		akPath := filepath.Join(home, ".ssh", "authorized_keys")
		content, err := os.ReadFile(akPath)
		if err != nil {
			continue
		}
		username := filepath.Base(home)
		if home == "/root" {
			username = "root"
		}
		keyCount := 0
		hasFrom := false
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			keyCount++
			if strings.HasPrefix(line, "from=") {
				hasFrom = true
			}
		}
		if keyCount > 0 {
			entries = append(entries, authKeyEntry{
				user: username, path: akPath, count: keyCount, hasFrom: hasFrom,
			})
		}
	}

	if len(entries) > 0 {
		totalKeys := 0
		for _, e := range entries {
			totalKeys += e.count
		}
		sb.WriteString(fmt.Sprintf("\n[Authorized Keys] %d user(s), %d total key(s):\n", len(entries), totalKeys))
		for _, e := range entries {
			restriction := ""
			if e.hasFrom {
				restriction = " (has from= restrictions)"
			}
			sb.WriteString(fmt.Sprintf("  %s: %d key(s) in %s%s\n", e.user, e.count, e.path, restriction))
		}
	} else {
		sb.WriteString("\n[Authorized Keys] No accessible authorized_keys files found\n")
	}

	return sb.String()
}
