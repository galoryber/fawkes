//go:build !windows

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestShellConfigName(t *testing.T) {
	cmd := &ShellConfigCommand{}
	if cmd.Name() != "shell-config" {
		t.Errorf("expected 'shell-config', got %q", cmd.Name())
	}
}

func TestShellConfigEmptyParams(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestShellConfigBadJSON(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestShellConfigInvalidAction(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action error, got %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigList(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Shell Config Files") {
		t.Errorf("expected 'Shell Config Files' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Shell History Files") {
		t.Errorf("expected 'Shell History Files' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "System-wide Config Files") {
		t.Errorf("expected 'System-wide Config Files' in output, got: %s", result.Output)
	}
}

func TestShellConfigHistory(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"history"}`})
	// Should succeed even if no history files (shows "No shell history files found")
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigReadMissingFile(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"read"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "file parameter required") {
		t.Errorf("expected file required error, got %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigReadNonexistent(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"read","file":"/tmp/nonexistent_shell_config_test"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "Error reading") {
		t.Errorf("expected error reading, got %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigInjectMissingFile(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"inject"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "file parameter required") {
		t.Errorf("expected file required error, got %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigInjectMissingLine(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"inject","file":".bashrc"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "line parameter required") {
		t.Errorf("expected line required error, got %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigRemoveMissingFile(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"remove"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "file parameter required") {
		t.Errorf("expected file required error, got %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigRemoveMissingLine(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"remove","file":".bashrc"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "line parameter required") {
		t.Errorf("expected line required error, got %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigInjectRemoveLifecycle(t *testing.T) {
	// Create a temp file to act as a shell config
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_bashrc")
	os.WriteFile(testFile, []byte("# existing config\nexport PATH=/usr/bin\n"), 0644)

	cmd := &ShellConfigCommand{}

	// Inject a line
	result := cmd.Execute(structs.Task{Params: `{"action":"inject","file":"` + testFile + `","line":"export PAYLOAD=/tmp/payload","comment":"fawkes"}`})
	if result.Status != "success" || !strings.Contains(result.Output, "Injected into") {
		t.Errorf("inject failed: %s: %s", result.Status, result.Output)
	}

	// Read it back
	result = cmd.Execute(structs.Task{Params: `{"action":"read","file":"` + testFile + `"}`})
	if result.Status != "success" || !strings.Contains(result.Output, "export PAYLOAD=/tmp/payload # fawkes") {
		t.Errorf("read after inject failed: %s: %s", result.Status, result.Output)
	}

	// Inject same line again — should skip
	result = cmd.Execute(structs.Task{Params: `{"action":"inject","file":"` + testFile + `","line":"export PAYLOAD=/tmp/payload","comment":"fawkes"}`})
	if result.Status != "success" || !strings.Contains(result.Output, "already exists") {
		t.Errorf("duplicate inject should skip: %s: %s", result.Status, result.Output)
	}

	// Remove the line
	result = cmd.Execute(structs.Task{Params: `{"action":"remove","file":"` + testFile + `","line":"export PAYLOAD=/tmp/payload"}`})
	if result.Status != "success" || !strings.Contains(result.Output, "Removed 1 line(s)") {
		t.Errorf("remove failed: %s: %s", result.Status, result.Output)
	}

	// Verify it's gone
	result = cmd.Execute(structs.Task{Params: `{"action":"read","file":"` + testFile + `"}`})
	if result.Status != "success" || strings.Contains(result.Output, "PAYLOAD") {
		t.Errorf("line should be removed: %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigHistoryWithFile(t *testing.T) {
	// Create a temp history file
	tmpDir := t.TempDir()
	histFile := filepath.Join(tmpDir, ".bash_history")
	lines := []string{
		"ls -la",
		"cd /etc",
		"cat /etc/passwd",
		"ssh admin@10.0.0.1",
		"mysql -u root -p secretpass",
	}
	os.WriteFile(histFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)

	// Can't directly test with default home dir, but we can test read action on the file
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"read","file":"` + histFile + `"}`})
	if result.Status != "success" {
		t.Errorf("expected success reading history file: %s", result.Output)
	}
	if !strings.Contains(result.Output, "ssh admin@10.0.0.1") {
		t.Errorf("expected history content in output: %s", result.Output)
	}
}

func TestShellConfigRemoveNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_rc")
	os.WriteFile(testFile, []byte("# config\nexport FOO=bar\n"), 0644)

	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"remove","file":"` + testFile + `","line":"NONEXISTENT_LINE"}`})
	if result.Status != "success" || !strings.Contains(result.Output, "Line not found") {
		t.Errorf("expected 'Line not found', got %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigPlainTextHistory(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: "history"})
	if result.Status != "success" {
		t.Errorf("plain text 'history' should succeed, got %s: %s", result.Status, result.Output)
	}
}

func TestShellConfigPlainTextList(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: "list"})
	if result.Status != "success" {
		t.Errorf("plain text 'list' should succeed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Shell Config Files") {
		t.Errorf("expected config files section in output")
	}
}

func TestShellConfigPlainTextReadFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_rc")
	os.WriteFile(testFile, []byte("export FOO=bar\n"), 0644)

	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: "read " + testFile})
	if result.Status != "success" {
		t.Errorf("plain text 'read <file>' should succeed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "FOO=bar") {
		t.Errorf("should contain file content: %s", result.Output)
	}
}
