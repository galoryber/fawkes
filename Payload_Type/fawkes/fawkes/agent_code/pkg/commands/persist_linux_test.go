//go:build linux

package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPersistLinux_NameAndDescription(t *testing.T) {
	cmd := &PersistCommand{}
	if cmd.Name() != "persist" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "persist")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestPersistLinux_EmptyParams(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestPersistLinux_InvalidJSON(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestPersistLinux_UnknownMethod(t *testing.T) {
	cmd := &PersistCommand{}
	params, _ := json.Marshal(persistArgs{Method: "unknown-method"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown method, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown method") {
		t.Errorf("expected 'Unknown method' in output, got: %s", result.Output)
	}
}

func TestPersistLinux_DefaultActionIsInstall(t *testing.T) {
	cmd := &PersistCommand{}
	// Missing path should fail install validation, but the routing should reach install
	params, _ := json.Marshal(persistArgs{Method: "crontab"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing path, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "path") {
		t.Errorf("expected path-related error, got: %s", result.Output)
	}
}

func TestPersistLinux_UnknownAction(t *testing.T) {
	cmd := &PersistCommand{}
	for _, method := range []string{"crontab", "systemd", "shell-profile", "ssh-key"} {
		t.Run(method, func(t *testing.T) {
			params, _ := json.Marshal(persistArgs{Method: method, Action: "badaction"})
			result := cmd.Execute(structs.Task{Params: string(params)})
			if result.Status != "error" {
				t.Errorf("expected error for unknown action on %s, got %q", method, result.Status)
			}
		})
	}
}

func TestPersistLinux_MethodAliases(t *testing.T) {
	cmd := &PersistCommand{}
	// All these aliases should route to a handler (and fail on missing path, not unknown method)
	aliases := []string{"crontab", "cron", "systemd", "systemd-service", "shell-profile", "shell", "bashrc", "ssh-key", "authorized-keys"}
	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			params, _ := json.Marshal(persistArgs{Method: alias})
			result := cmd.Execute(structs.Task{Params: string(params)})
			// Should NOT be "Unknown method" error
			if strings.Contains(result.Output, "Unknown method") {
				t.Errorf("method alias %q should be recognized but got Unknown method error", alias)
			}
		})
	}
}

func TestPersistLinux_CrontabMissingPath(t *testing.T) {
	result := persistCrontab(persistArgs{Action: "install"})
	if result.Status != "error" {
		t.Errorf("expected error for missing path, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "path") {
		t.Errorf("expected path-related error, got: %s", result.Output)
	}
}

func TestPersistLinux_SystemdMissingPath(t *testing.T) {
	result := persistSystemd(persistArgs{Action: "install"})
	if result.Status != "error" {
		t.Errorf("expected error for missing path, got %q", result.Status)
	}
}

func TestPersistLinux_ShellProfileMissingPath(t *testing.T) {
	result := persistShellProfile(persistArgs{Action: "install"})
	if result.Status != "error" {
		t.Errorf("expected error for missing path, got %q", result.Status)
	}
}

func TestPersistLinux_SSHKeyMissingPath(t *testing.T) {
	result := persistSSHKey(persistArgs{Action: "install"})
	if result.Status != "error" {
		t.Errorf("expected error for missing path, got %q", result.Status)
	}
}

// withTempHome runs a test function with HOME set to a temp directory
func withTempHome(t *testing.T, fn func(tmpHome string)) {
	t.Helper()
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	fn(tmpHome)
}

func TestPersistLinux_ShellProfileInstallAndRemove(t *testing.T) {
	withTempHome(t, func(tmpHome string) {
		// Create a .bashrc to install into
		bashrcPath := filepath.Join(tmpHome, ".bashrc")
		os.WriteFile(bashrcPath, []byte("# existing bashrc\n"), 0644)

		// Install
		result := persistShellProfileInstall(persistArgs{
			Path: "/tmp/test-agent",
			Name: "test-marker",
		})
		if result.Status != "success" {
			t.Fatalf("install failed: %s", result.Output)
		}
		if !strings.Contains(result.Output, "test-marker") {
			t.Errorf("output should mention marker, got: %s", result.Output)
		}

		// Verify file content
		data, _ := os.ReadFile(bashrcPath)
		content := string(data)
		if !strings.Contains(content, "# BEGIN test-marker") {
			t.Error("bashrc should contain BEGIN marker")
		}
		if !strings.Contains(content, "# END test-marker") {
			t.Error("bashrc should contain END marker")
		}
		if !strings.Contains(content, "nohup /tmp/test-agent") {
			t.Error("bashrc should contain the command")
		}

		// Duplicate install should fail
		result2 := persistShellProfileInstall(persistArgs{
			Path: "/tmp/test-agent",
			Name: "test-marker",
		})
		if result2.Status != "error" {
			t.Error("duplicate install should fail")
		}

		// Remove
		result3 := persistShellProfileRemove(persistArgs{Name: "test-marker"})
		if result3.Status != "success" {
			t.Fatalf("remove failed: %s", result3.Output)
		}

		// Verify marker block removed
		data, _ = os.ReadFile(bashrcPath)
		content = string(data)
		if strings.Contains(content, "test-marker") {
			t.Error("bashrc should not contain marker after removal")
		}
		if !strings.Contains(content, "# existing bashrc") {
			t.Error("existing content should be preserved")
		}
	})
}

func TestPersistLinux_ShellProfileDefaultMarker(t *testing.T) {
	withTempHome(t, func(tmpHome string) {
		bashrcPath := filepath.Join(tmpHome, ".bashrc")
		os.WriteFile(bashrcPath, []byte(""), 0644)

		result := persistShellProfileInstall(persistArgs{Path: "/tmp/agent"})
		if result.Status != "success" {
			t.Fatalf("install failed: %s", result.Output)
		}

		data, _ := os.ReadFile(bashrcPath)
		if !strings.Contains(string(data), "# BEGIN fawkes") {
			t.Error("default marker should be 'fawkes'")
		}

		// Cleanup
		persistShellProfileRemove(persistArgs{})
	})
}

func TestPersistLinux_ShellProfileRemoveNonexistent(t *testing.T) {
	withTempHome(t, func(tmpHome string) {
		// Create profiles without markers
		os.WriteFile(filepath.Join(tmpHome, ".bashrc"), []byte("clean\n"), 0644)

		result := persistShellProfileRemove(persistArgs{Name: "nonexistent"})
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent marker, got %q", result.Status)
		}
	})
}

func TestPersistLinux_SSHKeyInstallAndRemove(t *testing.T) {
	withTempHome(t, func(tmpHome string) {
		// Install SSH key
		testKey := "ssh-rsa AAAAB3NzaC1yc2EAAA..."
		result := persistSSHKeyInstall(persistArgs{
			Path: testKey,
			Name: "test-key",
		})
		if result.Status != "success" {
			t.Fatalf("install failed: %s", result.Output)
		}

		// Verify file
		authKeysPath := filepath.Join(tmpHome, ".ssh", "authorized_keys")
		data, err := os.ReadFile(authKeysPath)
		if err != nil {
			t.Fatalf("authorized_keys should exist: %v", err)
		}
		content := string(data)
		if !strings.Contains(content, testKey) {
			t.Error("authorized_keys should contain the key")
		}
		if !strings.Contains(content, "test-key") {
			t.Error("authorized_keys should contain the marker")
		}

		// Check permissions
		info, _ := os.Stat(authKeysPath)
		if info.Mode().Perm() != 0600 {
			t.Errorf("authorized_keys should be 0600, got %o", info.Mode().Perm())
		}

		// Duplicate install should fail
		result2 := persistSSHKeyInstall(persistArgs{
			Path: testKey,
			Name: "test-key",
		})
		if result2.Status != "error" {
			t.Error("duplicate install should fail")
		}

		// Remove
		result3 := persistSSHKeyRemove(persistArgs{Name: "test-key"})
		if result3.Status != "success" {
			t.Fatalf("remove failed: %s", result3.Output)
		}

		data, _ = os.ReadFile(authKeysPath)
		if strings.Contains(string(data), "test-key") {
			t.Error("authorized_keys should not contain marker after removal")
		}
	})
}

func TestPersistLinux_SSHKeyRemoveNonexistent(t *testing.T) {
	withTempHome(t, func(tmpHome string) {
		// Create .ssh dir with empty authorized_keys
		sshDir := filepath.Join(tmpHome, ".ssh")
		os.MkdirAll(sshDir, 0700)
		os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte("ssh-rsa otherkey\n"), 0600)

		result := persistSSHKeyRemove(persistArgs{Name: "nonexistent"})
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent marker, got %q", result.Status)
		}
	})
}

func TestPersistLinux_SSHKeyDefaultMarker(t *testing.T) {
	withTempHome(t, func(tmpHome string) {
		result := persistSSHKeyInstall(persistArgs{Path: "ssh-rsa AAAA..."})
		if result.Status != "success" {
			t.Fatalf("install failed: %s", result.Output)
		}

		authKeysPath := filepath.Join(tmpHome, ".ssh", "authorized_keys")
		data, _ := os.ReadFile(authKeysPath)
		if !strings.Contains(string(data), " fawkes\n") {
			t.Error("default marker should be 'fawkes'")
		}

		// Cleanup
		persistSSHKeyRemove(persistArgs{})
	})
}

func TestPersistLinux_SSHKeyPreservesExisting(t *testing.T) {
	withTempHome(t, func(tmpHome string) {
		sshDir := filepath.Join(tmpHome, ".ssh")
		os.MkdirAll(sshDir, 0700)
		authKeysPath := filepath.Join(sshDir, "authorized_keys")
		os.WriteFile(authKeysPath, []byte("ssh-rsa existing-key user@host\n"), 0600)

		// Install new key
		persistSSHKeyInstall(persistArgs{Path: "ssh-rsa new-key", Name: "test"})

		// Remove only the new key
		persistSSHKeyRemove(persistArgs{Name: "test"})

		data, _ := os.ReadFile(authKeysPath)
		if !strings.Contains(string(data), "existing-key") {
			t.Error("existing key should be preserved after removal")
		}
	})
}

func TestPersistLinux_SystemdDefaultName(t *testing.T) {
	// Just test that the default name logic works (will fail at filesystem level)
	result := persistSystemdInstall(persistArgs{Path: "/tmp/agent"})
	// It will try to write and may fail, but the output should reference the default name
	if result.Status == "success" && !strings.Contains(result.Output, "fawkes-agent") {
		t.Error("default service name should be 'fawkes-agent'")
	}
}

func TestPersistLinux_ShellProfileMultipleProfiles(t *testing.T) {
	withTempHome(t, func(tmpHome string) {
		// Create both .bashrc and .zshrc with the marker
		for _, name := range []string{".bashrc", ".zshrc"} {
			path := filepath.Join(tmpHome, name)
			content := "# existing\n# BEGIN test-multi\nnohup /tmp/agent >/dev/null 2>&1 &\n# END test-multi\n"
			os.WriteFile(path, []byte(content), 0644)
		}

		// Remove should clean both files
		result := persistShellProfileRemove(persistArgs{Name: "test-multi"})
		if result.Status != "success" {
			t.Fatalf("remove failed: %s", result.Output)
		}
		if !strings.Contains(result.Output, "2 shell profile") {
			t.Errorf("should report 2 profiles cleaned, got: %s", result.Output)
		}

		// Verify both are clean
		for _, name := range []string{".bashrc", ".zshrc"} {
			data, _ := os.ReadFile(filepath.Join(tmpHome, name))
			if strings.Contains(string(data), "test-multi") {
				t.Errorf("%s should not contain marker after removal", name)
			}
		}
	})
}
