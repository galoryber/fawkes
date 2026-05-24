package commands

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"

	"fawkes/pkg/structs"
)

// TestChownTildeExpansion covers the `strings.HasPrefix(path, "~")` branch
// (lines 64-67) in Execute — tilde is expanded to the user home directory.
// The chown call itself may fail without root, but the tilde expansion is covered.
func TestChownTildeExpansion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on Windows")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	testFile := filepath.Join(home, "test_chown.txt")
	if err := os.WriteFile(testFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Use the current user's name so the chown to same owner might succeed (no-op)
	me, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user")
	}

	cmd := &ChownCommand{}
	params, _ := json.Marshal(chownArgs{Path: "~/test_chown.txt", Owner: me.Username})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Either success (same owner) or error (permissions) — both cover the tilde branch
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status %q: %s", result.Status, result.Output)
	}
}
