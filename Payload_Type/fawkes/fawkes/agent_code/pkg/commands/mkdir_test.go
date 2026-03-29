package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMkdirCommandName(t *testing.T) {
	assertCommandName(t, &MkdirCommand{}, "mkdir")
}

func TestMkdirNoParams(t *testing.T) {
	assertEmptyParamsError(t, &MkdirCommand{})
}

func TestMkdirSuccess(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "newdir")

	cmd := &MkdirCommand{}
	result := cmd.Execute(mockTask("mkdir", path))
	assertSuccess(t, result)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("should be a directory")
	}
}

func TestMkdirJSONParams(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "jsondir")

	cmd := &MkdirCommand{}
	result := cmd.Execute(mockTask("mkdir", `{"path":"`+path+`"}`))
	assertSuccess(t, result)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("directory should exist: %v", err)
	}
}

func TestMkdirNestedDirs(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "a", "b", "c")

	cmd := &MkdirCommand{}
	result := cmd.Execute(mockTask("mkdir", path))
	assertSuccess(t, result)
	assertOutputContains(t, result, "Successfully")
}
