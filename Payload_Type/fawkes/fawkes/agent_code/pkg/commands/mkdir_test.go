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

func TestMkdirJSONDirectoryKey(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "by-directory-key")

	cmd := &MkdirCommand{}
	result := cmd.Execute(mockTask("mkdir", `{"directory":"`+path+`"}`))
	assertSuccess(t, result)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("directory should exist: %v", err)
	}
}

func TestMkdirJSONFullPathKey(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "by-full-path")

	cmd := &MkdirCommand{}
	result := cmd.Execute(mockTask("mkdir", `{"full_path":"`+path+`"}`))
	assertSuccess(t, result)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("directory should exist: %v", err)
	}
}

func TestMkdirJSONUnknownKeyRejected(t *testing.T) {
	// JSON input with no recognized key must error out instead of treating
	// the raw JSON as a literal directory name. Reliability sweep observed
	// `{"foo":"/tmp/x"}` silently created a directory named with the raw
	// JSON on Linux (the characters are filesystem-legal there) which then
	// confused operators chasing the "Successfully created" message.
	cmd := &MkdirCommand{}
	result := cmd.Execute(mockTask("mkdir", `{"foo":"/tmp/should-not-create"}`))
	assertError(t, result)
	assertOutputContains(t, result, "no recognized key")

	if _, err := os.Stat(`/tmp/should-not-create`); err == nil {
		// Best-effort cleanup; the failure case above is the assertion.
		_ = os.Remove(`/tmp/should-not-create`)
		t.Fatalf("directory must not have been created")
	}
	// And ensure no literal-JSON-named directory leaked.
	matches, _ := filepath.Glob(`/tmp/{*`)
	for _, m := range matches {
		if info, err := os.Stat(m); err == nil && info.IsDir() {
			_ = os.RemoveAll(m)
			t.Fatalf("literal-JSON-named directory leaked: %s", m)
		}
	}
}
