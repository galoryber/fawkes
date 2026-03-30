package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRmCommandName(t *testing.T) {
	assertCommandName(t, &RmCommand{}, "rm")
}

func TestRmNoParams(t *testing.T) {
	assertEmptyParamsError(t, &RmCommand{})
}

func TestRmFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "deleteme.txt")
	os.WriteFile(path, []byte("x"), 0644)

	cmd := &RmCommand{}
	result := cmd.Execute(mockTask("rm", path))
	assertSuccess(t, result)
	assertOutputContains(t, result, "file")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be deleted")
	}
}

func TestRmDirectory(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "deldir")
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "sub", "file.txt"), []byte("x"), 0644)

	cmd := &RmCommand{}
	result := cmd.Execute(mockTask("rm", dir))
	assertSuccess(t, result)
	assertOutputContains(t, result, "directory")
}

func TestRmNonexistent(t *testing.T) {
	cmd := &RmCommand{}
	result := cmd.Execute(mockTask("rm", "/nonexistent/path"))
	assertError(t, result)
}

func TestRmJSONParams(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "jsonrm.txt")
	os.WriteFile(path, []byte("x"), 0644)

	cmd := &RmCommand{}
	result := cmd.Execute(mockTask("rm", `{"path":"`+path+`"}`))
	assertSuccess(t, result)
}
