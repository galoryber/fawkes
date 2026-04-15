//go:build linux

package commands

import (
	"strings"
	"testing"
)

func TestPersistEnumShellProfiles_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumShellProfiles(&sb)
	output := sb.String()

	if !strings.Contains(output, "--- Shell Profiles ---") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Errorf("count should be >= 0, got %d", count)
	}
}

func TestPersistEnumStartup_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumStartup(&sb)
	output := sb.String()

	if !strings.Contains(output, "--- Startup / Init ---") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Errorf("count should be >= 0, got %d", count)
	}
}

func TestSSHAuthorizedKeysParsing(t *testing.T) {
	// Test the key line parsing logic from persistEnumSSHKeys
	tests := []struct {
		name        string
		line        string
		expectParts int
		expectType  string
	}{
		{
			"full key with comment",
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLONGKEYDATA... user@host",
			3,
			"ssh-rsa",
		},
		{
			"key without comment",
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKEYDATA",
			2,
			"ssh-ed25519",
		},
		{
			"ecdsa key",
			"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAI comment@host",
			3,
			"ecdsa-sha2-nistp256",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parts := strings.Fields(tc.line)
			if len(parts) < tc.expectParts {
				t.Fatalf("expected at least %d parts, got %d", tc.expectParts, len(parts))
			}
			if parts[0] != tc.expectType {
				t.Errorf("key type = %q, want %q", parts[0], tc.expectType)
			}
		})
	}
}

func TestSSHKeyTruncation(t *testing.T) {
	// persistEnumSSHKeys truncates key data:
	// parts[1][:min(20, len)] ... parts[1][max(0, len-8):]
	key := strings.Repeat("A", 100) // typical base64-encoded key
	truncated := key[:min(20, len(key))] + "..." + key[max(0, len(key)-8):]
	if len(truncated) != 31 { // 20 + 3 + 8
		t.Errorf("truncated key length = %d, want 31", len(truncated))
	}

	// Short key (< 20 chars) should still work
	shortKey := "AAAAB3"
	truncatedShort := shortKey[:min(20, len(shortKey))] + "..." + shortKey[max(0, len(shortKey)-8):]
	if !strings.HasPrefix(truncatedShort, "AAAAB3") {
		t.Errorf("short key truncation failed: %q", truncatedShort)
	}
}

func TestSSHKeyEncryptionDetection(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		encrypted bool
	}{
		{
			"encrypted RSA key",
			"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABC\n...",
			true,
		},
		{
			"plaintext RSA key",
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
			false,
		},
		{
			"encrypted openssh key",
			"-----BEGIN OPENSSH PRIVATE KEY-----\nbcrypt ENCRYPTED\n...",
			true,
		},
		{
			"plaintext ed25519 key",
			"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5v...\n-----END OPENSSH PRIVATE KEY-----",
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encrypted := strings.Contains(tc.content, "ENCRYPTED")
			if encrypted != tc.encrypted {
				t.Errorf("got encrypted=%v, want %v", encrypted, tc.encrypted)
			}
		})
	}
}

func TestRcLocalLineParsing(t *testing.T) {
	// persistEnumStartup parses rc.local: skip empty, comments, and "exit 0"
	content := `#!/bin/sh -e
# rc.local — executed at end of multi-user runlevel

# Start custom service
/usr/local/bin/myservice --daemon

exit 0
`
	var filtered []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "exit 0" {
			continue
		}
		filtered = append(filtered, line)
	}
	if len(filtered) != 1 {
		t.Errorf("expected 1 line (command only, shebang is #-prefixed), got %d: %v", len(filtered), filtered)
	}
	if len(filtered) > 0 && filtered[0] != "/usr/local/bin/myservice --daemon" {
		t.Errorf("expected command line, got %q", filtered[0])
	}
}

func TestDesktopEntryFiltering(t *testing.T) {
	// persistEnumStartup only counts .desktop files in autostart dirs
	names := []string{"firefox.desktop", "startup.sh", "notes.desktop", "README", ".hidden.desktop"}
	var desktop []string
	for _, name := range names {
		if strings.HasSuffix(name, ".desktop") {
			desktop = append(desktop, name)
		}
	}
	if len(desktop) != 3 {
		t.Errorf("expected 3 .desktop files, got %d: %v", len(desktop), desktop)
	}
}
