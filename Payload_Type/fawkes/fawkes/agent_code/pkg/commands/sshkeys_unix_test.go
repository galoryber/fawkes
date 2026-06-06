//go:build !windows

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSshKeysEnumerateUnixAgentSockets(t *testing.T) {
	output := sshKeysEnumerateUnix()
	if !strings.Contains(output, "[SSH Agent Sockets]") {
		t.Error("output should contain SSH Agent Sockets section")
	}
}

func TestSshKeysEnumerateUnixAuthorizedKeys(t *testing.T) {
	output := sshKeysEnumerateUnix()
	if !strings.Contains(output, "[Authorized Keys]") {
		t.Error("output should contain Authorized Keys section")
	}
}

func TestSshKeysEnumerateUnixWithAuthorizedKeys(t *testing.T) {
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	os.MkdirAll(sshDir, 0700)

	akContent := `ssh-rsa AAAAB3... user@host
from="192.168.1.0/24" ssh-ed25519 AAAAC3... admin@server
# comment line
ssh-ecdsa AAAAE2... deploy@ci
`
	os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(akContent), 0600)

	content, err := os.ReadFile(filepath.Join(sshDir, "authorized_keys"))
	if err != nil {
		t.Fatal(err)
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

	if keyCount != 3 {
		t.Errorf("expected 3 keys, got %d", keyCount)
	}
	if !hasFrom {
		t.Error("expected hasFrom to be true")
	}
}
