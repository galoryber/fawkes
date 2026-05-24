package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

// TestWriteFileMkDirsError covers the os.MkdirAll error path (line 67) —
// triggered when an ancestor path component is a regular file, not a directory.
func TestWriteFileMkDirsError(t *testing.T) {
	dir := t.TempDir()
	// Create a plain file where a directory segment needs to exist.
	blocker := filepath.Join(dir, "notadir")
	if err := os.WriteFile(blocker, []byte("block"), 0644); err != nil {
		t.Fatal(err)
	}

	c := &WriteFileCommand{}
	// /tmp/.../notadir/subpath/out.txt — MkdirAll fails because "notadir" is a file
	path := filepath.Join(blocker, "subpath", "out.txt")
	params, _ := json.Marshal(writeFileArgs{Path: path, Content: "hello", MkDirs: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error for MkDirs with file blocking dir creation, got %q: %s",
			result.Status, result.Output)
	}
}
