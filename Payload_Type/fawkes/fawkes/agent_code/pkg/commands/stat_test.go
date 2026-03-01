package commands

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestStatName(t *testing.T) {
	c := &StatCommand{}
	if c.Name() != "stat" {
		t.Errorf("expected 'stat', got '%s'", c.Name())
	}
}

func TestStatDescription(t *testing.T) {
	c := &StatCommand{}
	if c.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestStatEmptyParams(t *testing.T) {
	c := &StatCommand{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestStatBadJSON(t *testing.T) {
	c := &StatCommand{}
	result := c.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestStatMissingPath(t *testing.T) {
	c := &StatCommand{}
	params, _ := json.Marshal(statArgs{})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestStatNonexistentFile(t *testing.T) {
	c := &StatCommand{}
	params, _ := json.Marshal(statArgs{Path: "/nonexistent/file.txt"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestStatRegularFile(t *testing.T) {
	f, err := os.CreateTemp("", "stat_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte("hello world"))
	f.Close()

	c := &StatCommand{}
	params, _ := json.Marshal(statArgs{Path: f.Name()})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "regular file") {
		t.Error("should identify as regular file")
	}
	if !strings.Contains(result.Output, "11 bytes") || !strings.Contains(result.Output, "11 B") {
		t.Error("should show file size")
	}
	if !strings.Contains(result.Output, "Modify:") {
		t.Error("should show modification time")
	}
}

func TestStatDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("", "stat_test_dir_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	c := &StatCommand{}
	params, _ := json.Marshal(statArgs{Path: dir})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "directory") {
		t.Error("should identify as directory")
	}
}

func TestStatShowsPermissions(t *testing.T) {
	f, err := os.CreateTemp("", "stat_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	c := &StatCommand{}
	params, _ := json.Marshal(statArgs{Path: f.Name()})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Mode:") {
		t.Error("should show mode/permissions")
	}
}

func TestStatShowsOwnership(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ownership info differs on Windows")
	}

	f, err := os.CreateTemp("", "stat_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	c := &StatCommand{}
	params, _ := json.Marshal(statArgs{Path: f.Name()})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Owner:") {
		t.Error("should show owner on Unix")
	}
	if !strings.Contains(result.Output, "Inode:") {
		t.Error("should show inode on Unix")
	}
}

func TestStatFormatSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		result := statFormatSize(tt.bytes)
		if result != tt.expected {
			t.Errorf("statFormatSize(%d): expected '%s', got '%s'", tt.bytes, tt.expected, result)
		}
	}
}

func TestStatFileType(t *testing.T) {
	// Regular file
	f, err := os.CreateTemp("", "stat_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	info, _ := os.Stat(f.Name())
	if statFileType(info) != "regular file" {
		t.Errorf("expected 'regular file', got '%s'", statFileType(info))
	}

	// Directory
	dir, err := os.MkdirTemp("", "stat_test_dir_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	info, _ = os.Stat(dir)
	if statFileType(info) != "directory" {
		t.Errorf("expected 'directory', got '%s'", statFileType(info))
	}
}

func TestStatSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test not reliable on Windows")
	}

	f, err := os.CreateTemp("", "stat_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	link := f.Name() + "_link"
	if err := os.Symlink(f.Name(), link); err != nil {
		t.Skip("cannot create symlink")
	}
	defer os.Remove(link)

	c := &StatCommand{}
	params, _ := json.Marshal(statArgs{Path: link})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "symbolic link") {
		t.Error("should identify as symbolic link")
	}
	if !strings.Contains(result.Output, "Link:") {
		t.Error("should show link target")
	}
}
