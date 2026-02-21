//go:build !windows

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// ssh-keys file operation tests — covers sshKeysAdd, sshKeysRemove,
// sshKeysReadPrivate, sshKeysList with temp dirs (the 0% coverage functions)
// Basic parameter parsing tests are in commands_registry_test.go
// =============================================================================

func TestSSHKeysList_WithPath(t *testing.T) {
	tmpDir := t.TempDir()
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	content := "ssh-rsa AAAA... user@host\nssh-ed25519 BBBB... user2@host\n"
	if err := os.WriteFile(authKeysPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result := sshKeysList(sshKeysArgs{Path: authKeysPath})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "2 key(s)") {
		t.Errorf("expected 2 keys counted, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "ssh-rsa") {
		t.Errorf("expected key content in output, got: %s", result.Output)
	}
}

func TestSSHKeysList_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	if err := os.WriteFile(authKeysPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	result := sshKeysList(sshKeysArgs{Path: authKeysPath})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "(empty file)") {
		t.Errorf("expected '(empty file)' for empty authorized_keys, got: %s", result.Output)
	}
}

func TestSSHKeysList_WithComments(t *testing.T) {
	tmpDir := t.TempDir()
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	content := "# This is a comment\nssh-rsa AAAA... user@host\n# Another comment\n"
	if err := os.WriteFile(authKeysPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result := sshKeysList(sshKeysArgs{Path: authKeysPath})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "1 key(s)") {
		t.Errorf("expected 1 key (comments excluded), got: %s", result.Output)
	}
}

func TestSSHKeysList_NonexistentFile(t *testing.T) {
	result := sshKeysList(sshKeysArgs{Path: "/tmp/nonexistent_authorized_keys_test_fawkes"})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent file, got %q", result.Status)
	}
}

func TestSSHKeysAdd_MissingKey(t *testing.T) {
	result := sshKeysAdd(sshKeysArgs{Action: "add", Key: ""})
	if result.Status != "error" {
		t.Errorf("expected error for missing key, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "'key' is required") {
		t.Errorf("expected key required message, got: %s", result.Output)
	}
}

func TestSSHKeysAdd_NewKey(t *testing.T) {
	tmpDir := t.TempDir()
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")

	result := sshKeysAdd(sshKeysArgs{
		Key:  "ssh-rsa AAAA... testuser@testhost",
		Path: authKeysPath,
	})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Injected SSH key") {
		t.Errorf("expected injection message, got: %s", result.Output)
	}

	// Verify the key was written
	content, err := os.ReadFile(authKeysPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "ssh-rsa AAAA... testuser@testhost") {
		t.Errorf("key not found in file, content: %s", string(content))
	}
}

func TestSSHKeysAdd_DuplicateKey(t *testing.T) {
	tmpDir := t.TempDir()
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	existingKey := "ssh-rsa AAAA... testuser@testhost\n"
	if err := os.WriteFile(authKeysPath, []byte(existingKey), 0600); err != nil {
		t.Fatal(err)
	}

	result := sshKeysAdd(sshKeysArgs{
		Key:  "ssh-rsa AAAA... testuser@testhost",
		Path: authKeysPath,
	})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "already exists") {
		t.Errorf("expected 'already exists' message, got: %s", result.Output)
	}
}

func TestSSHKeysAdd_AppendToExisting(t *testing.T) {
	tmpDir := t.TempDir()
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	existingKey := "ssh-rsa AAAA... existing@host\n"
	if err := os.WriteFile(authKeysPath, []byte(existingKey), 0600); err != nil {
		t.Fatal(err)
	}

	result := sshKeysAdd(sshKeysArgs{
		Key:  "ssh-ed25519 BBBB... newuser@host",
		Path: authKeysPath,
	})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Verify both keys exist
	content, err := os.ReadFile(authKeysPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "existing@host") {
		t.Error("existing key should still be present")
	}
	if !strings.Contains(string(content), "newuser@host") {
		t.Error("new key should be present")
	}
}

func TestSSHKeysRemove_MissingKey(t *testing.T) {
	result := sshKeysRemove(sshKeysArgs{Action: "remove", Key: ""})
	if result.Status != "error" {
		t.Errorf("expected error for missing key, got %q", result.Status)
	}
}

func TestSSHKeysRemove_NonexistentFile(t *testing.T) {
	result := sshKeysRemove(sshKeysArgs{
		Key:  "testkey",
		Path: "/tmp/nonexistent_authorized_keys_test_fawkes",
	})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent file, got %q", result.Status)
	}
}

func TestSSHKeysRemove_KeyFound(t *testing.T) {
	tmpDir := t.TempDir()
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	content := "ssh-rsa AAAA... keep@host\nssh-ed25519 BBBB... remove@host\nssh-rsa CCCC... alsokeep@host\n"
	if err := os.WriteFile(authKeysPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result := sshKeysRemove(sshKeysArgs{
		Key:  "remove@host",
		Path: authKeysPath,
	})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Removed 1 key(s)") {
		t.Errorf("expected 'Removed 1 key(s)', got: %s", result.Output)
	}

	// Verify the key was removed and others remain
	newContent, err := os.ReadFile(authKeysPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(newContent), "remove@host") {
		t.Error("removed key should not be in file")
	}
	if !strings.Contains(string(newContent), "keep@host") {
		t.Error("kept key should still be in file")
	}
	if !strings.Contains(string(newContent), "alsokeep@host") {
		t.Error("other kept key should still be in file")
	}
}

func TestSSHKeysRemove_NoMatch(t *testing.T) {
	tmpDir := t.TempDir()
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	content := "ssh-rsa AAAA... user@host\n"
	if err := os.WriteFile(authKeysPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	result := sshKeysRemove(sshKeysArgs{
		Key:  "nonexistent@host",
		Path: authKeysPath,
	})
	if result.Status != "error" {
		t.Errorf("expected error for no match, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "No keys matching") {
		t.Errorf("expected 'No keys matching' message, got: %s", result.Output)
	}
}

func TestSSHKeysReadPrivate_SpecificPath(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_rsa")
	keyContent := "-----BEGIN RSA PRIVATE KEY-----\nfake-key-content\n-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(keyPath, []byte(keyContent), 0600); err != nil {
		t.Fatal(err)
	}

	result := sshKeysReadPrivate(sshKeysArgs{Path: keyPath})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "fake-key-content") {
		t.Errorf("expected key content in output, got: %s", result.Output)
	}
}

func TestSSHKeysReadPrivate_NonexistentPath(t *testing.T) {
	result := sshKeysReadPrivate(sshKeysArgs{Path: "/tmp/nonexistent_key_test_fawkes"})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent path, got %q", result.Status)
	}
}

func TestGetSSHDir_CurrentUser(t *testing.T) {
	dir, err := getSSHDir("")
	if err != nil {
		t.Fatalf("getSSHDir('') failed: %v", err)
	}
	if !strings.HasSuffix(dir, ".ssh") {
		t.Errorf("expected dir to end with .ssh, got %q", dir)
	}
}

func TestGetSSHDir_NonexistentUser(t *testing.T) {
	_, err := getSSHDir("nonexistent_user_12345_fawkes")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

// =============================================================================
// crontab error path tests
// Additional tests for crontabAdd and crontabRemove internal functions
// Basic parameter parsing tests are in commands_registry_test.go
// =============================================================================

func TestCrontabAdd_NoEntryOrProgram(t *testing.T) {
	result := crontabAdd(crontabArgs{Action: "add"})
	if result.Status != "error" {
		t.Errorf("expected error when neither entry nor program given, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "provide either") {
		t.Errorf("expected helpful error message, got: %s", result.Output)
	}
}

func TestCrontabRemove_NoEntryOrProgram(t *testing.T) {
	result := crontabRemove(crontabArgs{Action: "remove"})
	if result.Status != "error" {
		t.Errorf("expected error when neither entry nor program given, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "provide") {
		t.Errorf("expected helpful error message, got: %s", result.Output)
	}
}
