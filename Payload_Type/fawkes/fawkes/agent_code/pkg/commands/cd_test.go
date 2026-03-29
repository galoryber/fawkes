package commands

import (
	"os"
	"testing"
)

func TestCdCommandName(t *testing.T) {
	assertCommandName(t, &CdCommand{}, "cd")
}

func TestCdCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &CdCommand{})
}

func TestCdNoParams(t *testing.T) {
	assertEmptyParamsError(t, &CdCommand{})
}

func TestCdWithStringPath(t *testing.T) {
	tmp := t.TempDir()
	// Save and restore cwd
	orig, _ := os.Getwd()
	defer os.Chdir(orig)

	cmd := &CdCommand{}
	result := cmd.Execute(mockTask("cd", tmp))
	assertSuccess(t, result)
	assertOutputContains(t, result, tmp)
}

func TestCdWithJSONPath(t *testing.T) {
	tmp := t.TempDir()
	orig, _ := os.Getwd()
	defer os.Chdir(orig)

	cmd := &CdCommand{}
	result := cmd.Execute(mockTask("cd", `{"path":"`+tmp+`"}`))
	assertSuccess(t, result)
}

func TestCdNonexistentDir(t *testing.T) {
	cmd := &CdCommand{}
	result := cmd.Execute(mockTask("cd", "/nonexistent/dir/path"))
	assertError(t, result)
}

func TestCdEmptyJSONPath(t *testing.T) {
	cmd := &CdCommand{}
	result := cmd.Execute(mockTask("cd", `{"path":""}`))
	assertError(t, result)
}
