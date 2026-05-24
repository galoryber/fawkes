package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

// TestChmodTildeExpansion covers the `strings.HasPrefix(path, "~")` branch
// (lines 46-49) in Execute — tilde is expanded to the user home directory.
func TestChmodTildeExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create a file inside the temp home dir
	testFile := filepath.Join(home, "test_chmod.txt")
	if err := os.WriteFile(testFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Path: "~/test_chmod.txt", Mode: "755"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("chmod with tilde path failed: %s", result.Output)
	}

	// Verify permissions changed
	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("expected 0755, got %04o", info.Mode().Perm())
	}
}
