package agentfunctions

import (
	"testing"
)

func TestPersistMethodsForOS_Windows(t *testing.T) {
	methods := persistMethodsForOS("windows", "DESKTOP-ABC")
	if len(methods) != 3 {
		t.Fatalf("expected 3 methods, got %d", len(methods))
	}
	if methods[0] != "registry" {
		t.Errorf("expected registry first, got %s", methods[0])
	}
}

func TestPersistMethodsForOS_WinHostname(t *testing.T) {
	// When hostname contains "win", default to Windows even if OS is empty
	methods := persistMethodsForOS("", "WIN-SERVER01")
	if len(methods) != 3 {
		t.Fatalf("expected 3 methods for Windows hostname, got %d", len(methods))
	}
}

func TestPersistMethodsForOS_Linux(t *testing.T) {
	methods := persistMethodsForOS("linux", "ubuntu-server")
	if len(methods) != 3 {
		t.Fatalf("expected 3 methods, got %d", len(methods))
	}
	if methods[0] != "crontab" {
		t.Errorf("expected crontab first, got %s", methods[0])
	}
	if methods[1] != "shell-profile" {
		t.Errorf("expected shell-profile second, got %s", methods[1])
	}
	if methods[2] != "systemd" {
		t.Errorf("expected systemd third, got %s", methods[2])
	}
}

func TestPersistMethodsForOS_MacOS(t *testing.T) {
	methods := persistMethodsForOS("macos", "macbook")
	expected := []string{"launchagent", "folder-action", "login-item"}
	if len(methods) != len(expected) {
		t.Fatalf("expected %d methods, got %d: %v", len(expected), len(methods), methods)
	}
	for i, m := range expected {
		if methods[i] != m {
			t.Errorf("methods[%d] = %q, want %q", i, methods[i], m)
		}
	}
}

func TestPersistMethodsForOS_Darwin(t *testing.T) {
	methods := persistMethodsForOS("darwin", "macmini")
	expected := []string{"launchagent", "folder-action", "login-item"}
	if len(methods) != len(expected) {
		t.Fatalf("expected %d methods, got %d: %v", len(expected), len(methods), methods)
	}
	for i, m := range expected {
		if methods[i] != m {
			t.Errorf("methods[%d] = %q, want %q", i, methods[i], m)
		}
	}
}

func TestPersistMethodsForOS_EmptyDefaultsToWindows(t *testing.T) {
	methods := persistMethodsForOS("", "server01")
	// Empty OS with non-win hostname still defaults to Windows
	if len(methods) != 3 {
		t.Fatalf("expected 3 methods (Windows default), got %d", len(methods))
	}
}

func TestPersistMethodsForOS_UnknownOS(t *testing.T) {
	methods := persistMethodsForOS("freebsd", "bsd-host")
	if len(methods) != 2 {
		t.Fatalf("expected 2 methods (fallback), got %d", len(methods))
	}
}

func TestParsePersistListOutput_Standard(t *testing.T) {
	input := `Installed persistence mechanisms:
Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Name: FawkesUpdate
Value: C:\Users\admin\payload.exe
- Registry run key installed successfully
- Startup folder shortcut created
Total: 2 mechanisms installed`
	entries := parsePersistListOutput(input)
	// "- " prefix lines should be filtered, "Key:", "Name:", "Value:" lines kept, "=" lines filtered
	found := false
	for _, e := range entries {
		if e == "Total: 2 mechanisms installed" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Total: 2 mechanisms installed' in entries, got %v", entries)
	}
}

func TestParsePersistListOutput_Empty(t *testing.T) {
	entries := parsePersistListOutput("")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParsePersistListOutput_FiltersDashLines(t *testing.T) {
	input := `- first bullet
- second bullet
actual content`
	entries := parsePersistListOutput(input)
	if len(entries) != 1 || entries[0] != "actual content" {
		t.Errorf("expected [actual content], got %v", entries)
	}
}
