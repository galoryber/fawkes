package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestChmodName(t *testing.T) {
	c := &ChmodCommand{}
	if c.Name() != "chmod" {
		t.Errorf("expected 'chmod', got '%s'", c.Name())
	}
}

func TestChmodDescription(t *testing.T) {
	c := &ChmodCommand{}
	if c.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestChmodEmptyParams(t *testing.T) {
	c := &ChmodCommand{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestChmodBadJSON(t *testing.T) {
	c := &ChmodCommand{}
	result := c.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestChmodMissingPath(t *testing.T) {
	c := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Mode: "755"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "path") {
		t.Error("error should mention path")
	}
}

func TestChmodMissingMode(t *testing.T) {
	c := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Path: "/tmp/test"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "mode") {
		t.Error("error should mention mode")
	}
}

func TestChmodNonexistentFile(t *testing.T) {
	c := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Path: "/nonexistent/path/file.txt", Mode: "755"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestChmodOctalMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not fully supported on Windows")
	}

	// Create a temp file
	f, err := os.CreateTemp("", "chmod_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	// Set initial permissions
	os.Chmod(f.Name(), 0644)

	c := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Path: f.Name(), Mode: "755"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	// Verify permissions changed
	info, _ := os.Stat(f.Name())
	if info.Mode().Perm() != 0755 {
		t.Errorf("expected 0755, got %04o", info.Mode().Perm())
	}

	if !strings.Contains(result.Output, "0755") {
		t.Error("output should show new permissions")
	}
}

func TestChmodSymbolicPlusX(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not fully supported on Windows")
	}

	f, err := os.CreateTemp("", "chmod_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	os.Chmod(f.Name(), 0644)

	c := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Path: f.Name(), Mode: "+x"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	info, _ := os.Stat(f.Name())
	// +x on all: 0644 → 0755
	if info.Mode().Perm() != 0755 {
		t.Errorf("expected 0755, got %04o", info.Mode().Perm())
	}
}

func TestChmodSymbolicUserOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not fully supported on Windows")
	}

	f, err := os.CreateTemp("", "chmod_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	os.Chmod(f.Name(), 0644)

	c := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Path: f.Name(), Mode: "u+x"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	info, _ := os.Stat(f.Name())
	// u+x: 0644 → 0744
	if info.Mode().Perm() != 0744 {
		t.Errorf("expected 0744, got %04o", info.Mode().Perm())
	}
}

func TestChmodSymbolicMinusW(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not fully supported on Windows")
	}

	f, err := os.CreateTemp("", "chmod_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	os.Chmod(f.Name(), 0755)

	c := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Path: f.Name(), Mode: "go-w"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	info, _ := os.Stat(f.Name())
	// go-w on 0755: group/other already have no write, so stays 0755
	if info.Mode().Perm() != 0755 {
		t.Errorf("expected 0755, got %04o", info.Mode().Perm())
	}
}

func TestChmodSymbolicEquals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not fully supported on Windows")
	}

	f, err := os.CreateTemp("", "chmod_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	os.Chmod(f.Name(), 0777)

	c := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Path: f.Name(), Mode: "a=r"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	info, _ := os.Stat(f.Name())
	// a=r: 0777 → 0444
	if info.Mode().Perm() != 0444 {
		t.Errorf("expected 0444, got %04o", info.Mode().Perm())
	}
}

func TestChmodSymbolicComma(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not fully supported on Windows")
	}

	f, err := os.CreateTemp("", "chmod_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	os.Chmod(f.Name(), 0000)

	c := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Path: f.Name(), Mode: "u+rwx,go+rx"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	info, _ := os.Stat(f.Name())
	// u+rwx,go+rx on 0000: → 0755
	if info.Mode().Perm() != 0755 {
		t.Errorf("expected 0755, got %04o", info.Mode().Perm())
	}
}

func TestChmodInvalidOctal(t *testing.T) {
	c := &ChmodCommand{}

	f, err := os.CreateTemp("", "chmod_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	params, _ := json.Marshal(chmodArgs{Path: f.Name(), Mode: "999"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid octal, got %s", result.Status)
	}
}

func TestChmodInvalidSymbolic(t *testing.T) {
	c := &ChmodCommand{}

	f, err := os.CreateTemp("", "chmod_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	params, _ := json.Marshal(chmodArgs{Path: f.Name(), Mode: "z+q"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid symbolic mode, got %s", result.Status)
	}
}

func TestChmodRecursive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not fully supported on Windows")
	}

	// Create temp directory with files
	dir, err := os.MkdirTemp("", "chmod_test_dir_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Create some files
	for i := 0; i < 3; i++ {
		f, err := os.Create(filepath.Join(dir, fmt.Sprintf("file%d.txt", i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		os.Chmod(f.Name(), 0644)
	}

	// Create subdirectory with file
	subdir := filepath.Join(dir, "subdir")
	os.Mkdir(subdir, 0755)
	f, err := os.Create(filepath.Join(subdir, "nested.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	os.Chmod(f.Name(), 0644)

	c := &ChmodCommand{}
	params, _ := json.Marshal(chmodArgs{Path: dir, Mode: "755", Recursive: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	if !strings.Contains(result.Output, "items changed") {
		t.Error("output should mention items changed")
	}

	// Check nested file permissions
	info, _ := os.Stat(filepath.Join(subdir, "nested.txt"))
	if info.Mode().Perm() != 0755 {
		t.Errorf("nested file: expected 0755, got %04o", info.Mode().Perm())
	}
}

func TestChmodFormatPerm(t *testing.T) {
	tests := []struct {
		mode     os.FileMode
		expected string
	}{
		{0755, "rwxr-xr-x"},
		{0644, "rw-r--r--"},
		{0777, "rwxrwxrwx"},
		{0000, "---------"},
		{0700, "rwx------"},
	}

	for _, tt := range tests {
		result := chmodFormatPerm(tt.mode)
		if result != tt.expected {
			t.Errorf("chmodFormatPerm(%04o): expected '%s', got '%s'", tt.mode, tt.expected, result)
		}
	}
}

func TestChmodParseOctalModes(t *testing.T) {
	tests := []struct {
		input    string
		expected os.FileMode
	}{
		{"755", 0755},
		{"644", 0644},
		{"777", 0777},
		{"000", 0000},
		{"600", 0600},
	}

	for _, tt := range tests {
		mode, err := chmodParseMode(tt.input, 0)
		if err != nil {
			t.Errorf("chmodParseMode(%s): unexpected error: %v", tt.input, err)
			continue
		}
		if mode != tt.expected {
			t.Errorf("chmodParseMode(%s): expected %04o, got %04o", tt.input, tt.expected, mode)
		}
	}
}

func TestChmodParseModeInvalid(t *testing.T) {
	_, err := chmodParseMode("888", 0644)
	if err == nil {
		t.Error("expected error for octal mode 888")
	}
}
