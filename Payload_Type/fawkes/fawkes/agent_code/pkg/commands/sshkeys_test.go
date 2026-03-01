//go:build !windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSshKeysName(t *testing.T) {
	cmd := &SSHKeysCommand{}
	if cmd.Name() != "ssh-keys" {
		t.Errorf("expected 'ssh-keys', got %q", cmd.Name())
	}
}

func TestSshKeysDescription(t *testing.T) {
	cmd := &SSHKeysCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestSshKeysExecuteDefault(t *testing.T) {
	cmd := &SSHKeysCommand{}
	// Action "read-private" with no custom path searches default ~/.ssh paths
	params, _ := json.Marshal(sshKeysArgs{
		Action: "read-private",
	})
	task := structs.NewTask("t", "ssh-keys", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	// Should succeed — either finds keys or reports "No private keys found"
	if result.Status != "success" && result.Status != "error" {
		t.Fatalf("unexpected status %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestSshKeysExecuteCustomPath(t *testing.T) {
	// Create a temp directory to use as a custom path for authorized_keys
	tmp := t.TempDir()
	authKeysPath := filepath.Join(tmp, "authorized_keys")
	// Create an empty authorized_keys file
	os.WriteFile(authKeysPath, []byte(""), 0600)

	cmd := &SSHKeysCommand{}
	params, _ := json.Marshal(sshKeysArgs{
		Action: "list",
		Path:   authKeysPath,
	})
	task := structs.NewTask("t", "ssh-keys", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	// With an empty file, should report 0 keys
	if !strings.Contains(result.Output, "0 key(s)") && !strings.Contains(result.Output, "(empty file)") {
		t.Errorf("expected output to indicate 0 keys or empty file, got: %s", result.Output)
	}
}

// --- parseSSHConfig tests ---

func TestParseSSHConfig_BasicHosts(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config")
	os.WriteFile(configPath, []byte(`
Host webserver
    HostName 10.0.0.50
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_web

Host db-primary
    HostName db1.internal.corp
    User dba
`), 0600)

	hosts := parseSSHConfig(configPath)
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}

	if hosts[0].alias != "webserver" {
		t.Errorf("host[0].alias = %q, want %q", hosts[0].alias, "webserver")
	}
	if hosts[0].hostname != "10.0.0.50" {
		t.Errorf("host[0].hostname = %q, want %q", hosts[0].hostname, "10.0.0.50")
	}
	if hosts[0].user != "admin" {
		t.Errorf("host[0].user = %q, want %q", hosts[0].user, "admin")
	}
	if hosts[0].port != "2222" {
		t.Errorf("host[0].port = %q, want %q", hosts[0].port, "2222")
	}
	if hosts[0].identityFile != "~/.ssh/id_web" {
		t.Errorf("host[0].identityFile = %q", hosts[0].identityFile)
	}

	if hosts[1].alias != "db-primary" {
		t.Errorf("host[1].alias = %q", hosts[1].alias)
	}
	if hosts[1].hostname != "db1.internal.corp" {
		t.Errorf("host[1].hostname = %q", hosts[1].hostname)
	}
}

func TestParseSSHConfig_ProxyJumpAndProxyCommand(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config")
	os.WriteFile(configPath, []byte(`
Host target
    HostName 192.168.1.100
    ProxyJump bastion

Host hidden
    HostName 10.10.10.5
    ProxyCommand ssh -W %h:%p gateway
`), 0600)

	hosts := parseSSHConfig(configPath)
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}

	if hosts[0].proxyJump != "bastion" {
		t.Errorf("host[0].proxyJump = %q, want %q", hosts[0].proxyJump, "bastion")
	}
	if hosts[1].proxyCommand != "ssh -W %h:%p gateway" {
		t.Errorf("host[1].proxyCommand = %q", hosts[1].proxyCommand)
	}
}

func TestParseSSHConfig_WildcardSkipped(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config")
	os.WriteFile(configPath, []byte(`
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3

Host real-host
    HostName 10.0.0.1
`), 0600)

	hosts := parseSSHConfig(configPath)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host (wildcard skipped), got %d", len(hosts))
	}
	if hosts[0].alias != "real-host" {
		t.Errorf("host[0].alias = %q, want %q", hosts[0].alias, "real-host")
	}
}

func TestParseSSHConfig_EqualsFormat(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config")
	os.WriteFile(configPath, []byte(`Host equalstest
HostName=10.0.0.99
User=testuser
Port=9022
`), 0600)

	hosts := parseSSHConfig(configPath)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].hostname != "10.0.0.99" {
		t.Errorf("hostname = %q", hosts[0].hostname)
	}
	if hosts[0].user != "testuser" {
		t.Errorf("user = %q", hosts[0].user)
	}
	if hosts[0].port != "9022" {
		t.Errorf("port = %q", hosts[0].port)
	}
}

func TestParseSSHConfig_EmptyFile(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config")
	os.WriteFile(configPath, []byte(""), 0600)

	hosts := parseSSHConfig(configPath)
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts for empty config, got %d", len(hosts))
	}
}

func TestParseSSHConfig_NonExistent(t *testing.T) {
	hosts := parseSSHConfig("/nonexistent/path/config")
	if hosts != nil {
		t.Error("expected nil for non-existent config")
	}
}

func TestParseSSHConfig_CommentsAndBlankLines(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config")
	os.WriteFile(configPath, []byte(`
# This is a comment
Host myserver
    # Hostname comment
    HostName 10.0.0.1

    # Port comment
    User admin
`), 0600)

	hosts := parseSSHConfig(configPath)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].user != "admin" {
		t.Errorf("user = %q", hosts[0].user)
	}
}

// --- parseKnownHosts tests ---

func TestParseKnownHosts_PlainHosts(t *testing.T) {
	tmp := t.TempDir()
	khPath := filepath.Join(tmp, "known_hosts")
	os.WriteFile(khPath, []byte(`10.0.0.1 ssh-rsa AAAAB3...
github.com,140.82.121.3 ssh-ed25519 AAAAC3...
192.168.1.50 ecdsa-sha2-nistp256 AAAAE2...
`), 0600)

	hosts := parseKnownHosts(khPath)
	if len(hosts) != 4 { // github.com and 140.82.121.3 are separate entries
		t.Fatalf("expected 4 hosts, got %d", len(hosts))
	}

	// Check that we got all the hosts
	hostNames := make(map[string]string)
	for _, h := range hosts {
		hostNames[h.host] = h.keyType
	}
	if _, ok := hostNames["10.0.0.1"]; !ok {
		t.Error("missing 10.0.0.1")
	}
	if _, ok := hostNames["github.com"]; !ok {
		t.Error("missing github.com")
	}
	if _, ok := hostNames["140.82.121.3"]; !ok {
		t.Error("missing 140.82.121.3")
	}
	if _, ok := hostNames["192.168.1.50"]; !ok {
		t.Error("missing 192.168.1.50")
	}
}

func TestParseKnownHosts_HashedEntries(t *testing.T) {
	tmp := t.TempDir()
	khPath := filepath.Join(tmp, "known_hosts")
	os.WriteFile(khPath, []byte(`|1|abc123def456|ghijklmnop ssh-rsa AAAAB3...
|1|xyz789uvw012|qrstuvwxyz ssh-ed25519 AAAAC3...
10.0.0.1 ssh-rsa AAAAB3...
`), 0600)

	hosts := parseKnownHosts(khPath)
	hashedCount := 0
	plainCount := 0
	for _, h := range hosts {
		if h.hashed {
			hashedCount++
		} else {
			plainCount++
		}
	}
	if hashedCount != 2 {
		t.Errorf("expected 2 hashed hosts, got %d", hashedCount)
	}
	if plainCount != 1 {
		t.Errorf("expected 1 plain host, got %d", plainCount)
	}
}

func TestParseKnownHosts_BracketedPort(t *testing.T) {
	tmp := t.TempDir()
	khPath := filepath.Join(tmp, "known_hosts")
	os.WriteFile(khPath, []byte(`[10.0.0.1]:2222 ssh-rsa AAAAB3...
[example.com]:8022 ssh-ed25519 AAAAC3...
`), 0600)

	hosts := parseKnownHosts(khPath)
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}

	hostNames := make(map[string]bool)
	for _, h := range hosts {
		hostNames[h.host] = true
	}
	if !hostNames["10.0.0.1"] {
		t.Error("bracketed host 10.0.0.1 not parsed correctly")
	}
	if !hostNames["example.com"] {
		t.Error("bracketed host example.com not parsed correctly")
	}
}

func TestParseKnownHosts_Deduplication(t *testing.T) {
	tmp := t.TempDir()
	khPath := filepath.Join(tmp, "known_hosts")
	os.WriteFile(khPath, []byte(`10.0.0.1 ssh-rsa AAAAB3...
10.0.0.1 ssh-ed25519 AAAAC3...
10.0.0.1 ecdsa-sha2-nistp256 AAAAE2...
`), 0600)

	hosts := parseKnownHosts(khPath)
	if len(hosts) != 1 {
		t.Errorf("expected 1 deduplicated host, got %d", len(hosts))
	}
}

func TestParseKnownHosts_EmptyFile(t *testing.T) {
	tmp := t.TempDir()
	khPath := filepath.Join(tmp, "known_hosts")
	os.WriteFile(khPath, []byte(""), 0600)

	hosts := parseKnownHosts(khPath)
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts for empty file, got %d", len(hosts))
	}
}

func TestParseKnownHosts_NonExistent(t *testing.T) {
	hosts := parseKnownHosts("/nonexistent/path/known_hosts")
	if hosts != nil {
		t.Error("expected nil for non-existent known_hosts")
	}
}

// --- splitSSHConfigLine tests ---

func TestSplitSSHConfigLine_SpaceSeparated(t *testing.T) {
	key, val := splitSSHConfigLine("HostName 10.0.0.1")
	if key != "HostName" || val != "10.0.0.1" {
		t.Errorf("got key=%q val=%q", key, val)
	}
}

func TestSplitSSHConfigLine_EqualsSeparated(t *testing.T) {
	key, val := splitSSHConfigLine("HostName=10.0.0.1")
	if key != "HostName" || val != "10.0.0.1" {
		t.Errorf("got key=%q val=%q", key, val)
	}
}

func TestSplitSSHConfigLine_TabSeparated(t *testing.T) {
	key, val := splitSSHConfigLine("User\tadmin")
	if key != "User" || val != "admin" {
		t.Errorf("got key=%q val=%q", key, val)
	}
}

func TestSplitSSHConfigLine_ValueWithSpaces(t *testing.T) {
	key, val := splitSSHConfigLine("ProxyCommand ssh -W %h:%p bastion")
	if key != "ProxyCommand" || val != "ssh -W %h:%p bastion" {
		t.Errorf("got key=%q val=%q", key, val)
	}
}

// --- isStandardKeyFile tests ---

func TestIsStandardKeyFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"~/.ssh/id_rsa", true},
		{"~/.ssh/id_ed25519", true},
		{"~/.ssh/id_ecdsa", true},
		{"~/.ssh/id_dsa", true},
		{"~/.ssh/id_deploy_prod", false},
		{"/custom/path/mykey", false},
	}
	for _, tc := range cases {
		got := isStandardKeyFile(tc.path)
		if got != tc.want {
			t.Errorf("isStandardKeyFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// --- sshKeysEnumerate integration test ---

func TestSshKeysEnumerate_MockSSHDir(t *testing.T) {
	// Create a mock .ssh directory with config, known_hosts, and a key
	tmp := t.TempDir()
	sshDir := filepath.Join(tmp, ".ssh")
	os.MkdirAll(sshDir, 0700)

	// Write config
	os.WriteFile(filepath.Join(sshDir, "config"), []byte(`
Host prod-web
    HostName 10.10.10.50
    User deploy
    Port 2222
    ProxyJump bastion

Host bastion
    HostName bastion.example.com
    User admin
    IdentityFile ~/.ssh/id_bastion
`), 0600)

	// Write known_hosts
	os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(`bastion.example.com ssh-ed25519 AAAAC3...
10.10.10.50 ssh-rsa AAAAB3...
|1|hashed123456|hasheddata ssh-rsa AAAAB3...
`), 0600)

	// Write a fake private key
	os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA...
-----END OPENSSH PRIVATE KEY-----
`), 0600)

	// Write an encrypted key
	os.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte(`-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,...
-----END RSA PRIVATE KEY-----
`), 0600)

	// Call parseSSHConfig and parseKnownHosts directly since sshKeysEnumerate
	// uses getSSHDir which looks up actual user home directories
	configHosts := parseSSHConfig(filepath.Join(sshDir, "config"))
	if len(configHosts) != 2 {
		t.Fatalf("config: expected 2 hosts, got %d", len(configHosts))
	}
	if configHosts[0].proxyJump != "bastion" {
		t.Errorf("config: host[0].proxyJump = %q", configHosts[0].proxyJump)
	}

	knownHosts := parseKnownHosts(filepath.Join(sshDir, "known_hosts"))
	plainHosts := 0
	hashedHosts := 0
	for _, kh := range knownHosts {
		if kh.hashed {
			hashedHosts++
		} else {
			plainHosts++
		}
	}
	if plainHosts != 2 {
		t.Errorf("known_hosts: expected 2 plain hosts, got %d", plainHosts)
	}
	if hashedHosts != 1 {
		t.Errorf("known_hosts: expected 1 hashed host, got %d", hashedHosts)
	}
}

func TestSshKeysEnumerate_EmptyParams(t *testing.T) {
	cmd := &SSHKeysCommand{}
	params, _ := json.Marshal(sshKeysArgs{Action: "enumerate"})
	task := structs.NewTask("t", "ssh-keys", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	// Should succeed (uses current user's .ssh dir)
	if !result.Completed {
		t.Error("expected Completed=true")
	}
	if !strings.Contains(result.Output, "SSH Enumeration") {
		t.Errorf("output should contain 'SSH Enumeration', got: %s", result.Output)
	}
}

func TestSshKeysEnumerate_NonExistentUser(t *testing.T) {
	cmd := &SSHKeysCommand{}
	params, _ := json.Marshal(sshKeysArgs{
		Action: "enumerate",
		User:   fmt.Sprintf("nonexistentuser_%d", os.Getpid()),
	})
	task := structs.NewTask("t", "ssh-keys", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "error" {
		t.Errorf("expected error for non-existent user, got %q", result.Status)
	}
}

func TestSshKeysPlainTextEnumerate(t *testing.T) {
	cmd := &SSHKeysCommand{}
	result := cmd.Execute(structs.Task{Params: "enumerate"})
	if result.Status != "success" {
		t.Errorf("plain text 'enumerate' should succeed, got %s: %s", result.Status, result.Output)
	}
}

func TestSshKeysPlainTextList(t *testing.T) {
	cmd := &SSHKeysCommand{}
	result := cmd.Execute(structs.Task{Params: "list"})
	if result.Status != "success" {
		t.Errorf("plain text 'list' should succeed, got %s: %s", result.Status, result.Output)
	}
}
