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

func TestChmodParseModeOctalTooLarge(t *testing.T) {
	// "1000" is valid octal (512 decimal) but > 0777 (511 decimal)
	_, err := chmodParseMode("1000", 0644)
	if err == nil {
		t.Error("expected error for octal mode > 0777")
	}
	if err != nil && !strings.Contains(err.Error(), "too large") {
		t.Errorf("error should mention 'too large', got: %v", err)
	}
}

func TestChmodParseModeOctalBoundary(t *testing.T) {
	// "777" is exactly at the boundary — should succeed
	mode, err := chmodParseMode("777", 0)
	if err != nil {
		t.Fatalf("unexpected error for mode 777: %v", err)
	}
	if mode != 0777 {
		t.Errorf("expected 0777, got %04o", mode)
	}
}

// --- chmodParseSymbolic direct tests ---

func TestChmodParseSymbolic_MultiClause(t *testing.T) {
	// u+rwx,g+rx,o+r on 0000 → 0754
	mode, err := chmodParseSymbolic("u+rwx,g+rx,o+r", 0000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != 0754 {
		t.Errorf("expected 0754, got %04o", mode)
	}
}

func TestChmodParseSymbolic_EqualsUser(t *testing.T) {
	// u=rw on 0777 → only user changes, group/other preserved
	mode, err := chmodParseSymbolic("u=rw", 0777)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// u=rw: user becomes rw- (6), group/other stay 7,7 → 0677
	if mode != 0677 {
		t.Errorf("expected 0677, got %04o", mode)
	}
}

func TestChmodParseSymbolic_EqualsGroup(t *testing.T) {
	// g=rx on 0777 → group becomes r-x, user/other preserved
	mode, err := chmodParseSymbolic("g=rx", 0777)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != 0757 {
		t.Errorf("expected 0757, got %04o", mode)
	}
}

func TestChmodParseSymbolic_MinusAll(t *testing.T) {
	// -rwx on 0777 → 0000
	mode, err := chmodParseSymbolic("-rwx", 0777)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != 0000 {
		t.Errorf("expected 0000, got %04o", mode)
	}
}

func TestChmodParseSymbolic_InvalidWho(t *testing.T) {
	_, err := chmodParseSymbolic("z+r", 0644)
	if err == nil {
		t.Error("expected error for invalid who character 'z'")
	}
	if !strings.Contains(err.Error(), "invalid who character") {
		t.Errorf("error should mention invalid who character, got: %v", err)
	}
}

func TestChmodParseSymbolic_InvalidPermChar(t *testing.T) {
	_, err := chmodParseSymbolic("u+q", 0644)
	if err == nil {
		t.Error("expected error for invalid permission character 'q'")
	}
	if !strings.Contains(err.Error(), "invalid permission character") {
		t.Errorf("error should mention invalid permission, got: %v", err)
	}
}

func TestChmodParseSymbolic_MissingOperator(t *testing.T) {
	_, err := chmodParseSymbolic("urwx", 0644)
	if err == nil {
		t.Error("expected error for missing operator")
	}
}

func TestChmodParseSymbolic_TooShort(t *testing.T) {
	_, err := chmodParseSymbolic("x", 0644)
	if err == nil {
		t.Error("expected error for single-char mode")
	}
}

func TestChmodParseSymbolic_OtherEquals(t *testing.T) {
	// o=rw on 0755 → other becomes rw- (6), user/group preserved → 0756
	mode, err := chmodParseSymbolic("o=rw", 0755)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != 0756 {
		t.Errorf("expected 0756, got %04o", mode)
	}
}

func TestChmodParseSymbolic_MultiWho(t *testing.T) {
	// ug+x on 0600 → user and group get execute → 0710
	mode, err := chmodParseSymbolic("ug+x", 0600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != 0710 {
		t.Errorf("expected 0710, got %04o", mode)
	}
}

// --- chmodFormatResult tests ---

func TestChmodFormatResult_Basic(t *testing.T) {
	result := chmodFormatResult("/tmp/test.txt", 0644, 0755)
	if !strings.Contains(result, "/tmp/test.txt") {
		t.Error("output should contain path")
	}
	if !strings.Contains(result, "Before:") {
		t.Error("output should contain Before")
	}
	if !strings.Contains(result, "After:") {
		t.Error("output should contain After")
	}
	if !strings.Contains(result, "rw-r--r--") {
		t.Error("output should show 0644 in rwx format")
	}
	if !strings.Contains(result, "rwxr-xr-x") {
		t.Error("output should show 0755 in rwx format")
	}
	if !strings.Contains(result, "0644") {
		t.Error("output should show octal 0644")
	}
	if !strings.Contains(result, "0755") {
		t.Error("output should show octal 0755")
	}
}

func TestChmodFormatResult_SamePerm(t *testing.T) {
	result := chmodFormatResult("/tmp/file", 0644, 0644)
	// Should still format even if same
	if !strings.Contains(result, "Before:") || !strings.Contains(result, "After:") {
		t.Error("output should show before/after even when same")
	}
}
