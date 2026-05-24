//go:build linux

package commands

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheck1PasswordFound covers the `os.Stat succeeds → append result` branch
// in check1Password (lines 152-158) on Linux.
func TestCheck1PasswordFound(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "1Password")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}

	var results []pmResult
	check1Password(home, &results)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Manager != "1Password" {
		t.Errorf("expected 1Password, got %q", results[0].Manager)
	}
}

// TestCheckBitwardenFoundWithDataJSON covers the `data.json exists` branch
// in checkBitwarden (lines 183-185) that adds size info to the detail string.
func TestCheckBitwardenFoundWithDataJSON(t *testing.T) {
	home := t.TempDir()
	bwDir := filepath.Join(home, ".config", "Bitwarden")
	if err := os.MkdirAll(bwDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Create data.json to trigger the detail branch
	if err := os.WriteFile(filepath.Join(bwDir, "data.json"), []byte(`{"encrypted":"vault"}`), 0600); err != nil {
		t.Fatal(err)
	}

	var results []pmResult
	checkBitwarden(home, &results)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Manager != "Bitwarden" {
		t.Errorf("expected Bitwarden, got %q", results[0].Manager)
	}
	// The detail should mention data.json (not the generic fallback)
	if results[0].Details == "Bitwarden desktop data directory" {
		t.Error("expected data.json detail, got generic fallback")
	}
}

// TestCheckBitwardenFoundNoDataJSON covers the `no data.json → generic detail` branch
// in checkBitwarden — directory exists but data.json is absent.
func TestCheckBitwardenFoundNoDataJSON(t *testing.T) {
	home := t.TempDir()
	bwDir := filepath.Join(home, ".config", "Bitwarden")
	if err := os.MkdirAll(bwDir, 0755); err != nil {
		t.Fatal(err)
	}

	var results []pmResult
	checkBitwarden(home, &results)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Details != "Bitwarden desktop data directory" {
		t.Errorf("expected generic detail, got %q", results[0].Details)
	}
}

// TestCheckLastPassFound covers the `os.Stat succeeds → append result` branch
// in checkLastPass on Linux — requires a Chrome profile with the LastPass extension dir.
func TestCheckLastPassFound(t *testing.T) {
	home := t.TempDir()
	lastPassExtID := "hdokiejnpimakedhajhdlcegeplioahd"
	extDir := filepath.Join(home, ".config", "google-chrome", "Default", "Extensions", lastPassExtID)
	if err := os.MkdirAll(extDir, 0755); err != nil {
		t.Fatal(err)
	}

	var results []pmResult
	checkLastPass(home, &results)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Manager != "LastPass" {
		t.Errorf("expected LastPass, got %q", results[0].Manager)
	}
}

// TestCheckDashlaneFound covers the `os.Stat succeeds → append result` branch
// in checkDashlane on Linux.
func TestCheckDashlaneFound(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "dashlane")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}

	var results []pmResult
	checkDashlane(home, &results)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Manager != "Dashlane" {
		t.Errorf("expected Dashlane, got %q", results[0].Manager)
	}
}

// TestCheckKeePassXCFoundWithINI covers the `keepassxc.ini exists` branch
// in checkKeePassXC (lines 290-292) that changes the detail string.
func TestCheckKeePassXCFoundWithINI(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "keepassxc")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	// Create keepassxc.ini to trigger the ini branch
	if err := os.WriteFile(filepath.Join(dir, "keepassxc.ini"), []byte("[General]\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var results []pmResult
	checkKeePassXC(home, &results)
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if results[0].Manager != "KeePassXC" {
		t.Errorf("expected KeePassXC, got %q", results[0].Manager)
	}
	// Should have the INI-specific detail
	if results[0].Details != "KeePassXC config (may contain recent database paths)" {
		t.Errorf("unexpected detail: %q", results[0].Details)
	}
}

// TestCheckKeePassXCFoundNoINI covers the `no keepassxc.ini → generic detail` branch
// in checkKeePassXC — directory exists but INI file is absent.
func TestCheckKeePassXCFoundNoINI(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "keepassxc")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}

	var results []pmResult
	checkKeePassXC(home, &results)
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if results[0].Details != "KeePassXC configuration directory" {
		t.Errorf("expected generic detail, got %q", results[0].Details)
	}
}
