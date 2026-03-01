package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"fawkes/pkg/structs"
)

func TestLnCommand_Name(t *testing.T) {
	cmd := &LnCommand{}
	if cmd.Name() != "ln" {
		t.Errorf("expected 'ln', got '%s'", cmd.Name())
	}
}

func makeLnTask(args lnArgs) structs.Task {
	b, _ := json.Marshal(args)
	return structs.Task{Params: string(b)}
}

func TestLnCommand_EmptyParams(t *testing.T) {
	cmd := &LnCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
}

func TestLnCommand_MissingTarget(t *testing.T) {
	cmd := &LnCommand{}
	result := cmd.Execute(makeLnTask(lnArgs{Link: "/tmp/link"}))
	if result.Status != "error" {
		t.Error("expected error for missing target")
	}
}

func TestLnCommand_MissingLink(t *testing.T) {
	cmd := &LnCommand{}
	result := cmd.Execute(makeLnTask(lnArgs{Target: "/tmp/file"}))
	if result.Status != "error" {
		t.Error("expected error for missing link")
	}
}

func TestLnCommand_HardLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard link test on Unix only")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "original.txt")
	link := filepath.Join(dir, "hardlink.txt")

	os.WriteFile(target, []byte("test content"), 0644)

	cmd := &LnCommand{}
	result := cmd.Execute(makeLnTask(lnArgs{Target: target, Link: link}))
	if result.Status == "error" {
		t.Fatalf("hard link failed: %s", result.Output)
	}

	// Verify link exists and has same content
	content, err := os.ReadFile(link)
	if err != nil {
		t.Fatalf("failed to read hard link: %v", err)
	}
	if string(content) != "test content" {
		t.Errorf("expected 'test content', got '%s'", string(content))
	}

	// Verify same inode (hard link)
	targetInfo, _ := os.Stat(target)
	linkInfo, _ := os.Stat(link)
	if !os.SameFile(targetInfo, linkInfo) {
		t.Error("hard link does not reference same file")
	}
}

func TestLnCommand_Symlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test on Unix only")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "original.txt")
	link := filepath.Join(dir, "symlink.txt")

	os.WriteFile(target, []byte("symlink content"), 0644)

	cmd := &LnCommand{}
	result := cmd.Execute(makeLnTask(lnArgs{Target: target, Link: link, Symbolic: true}))
	if result.Status == "error" {
		t.Fatalf("symlink failed: %s", result.Output)
	}

	// Verify it's a symlink
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("failed to lstat link: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("expected symlink, got regular file")
	}

	// Verify target resolution
	resolved, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("failed to readlink: %v", err)
	}
	if resolved != target {
		t.Errorf("expected target '%s', got '%s'", target, resolved)
	}
}

func TestLnCommand_SymlinkToNonExistent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test on Unix only")
	}

	dir := t.TempDir()
	link := filepath.Join(dir, "dangling.txt")

	cmd := &LnCommand{}
	result := cmd.Execute(makeLnTask(lnArgs{Target: "/nonexistent/path", Link: link, Symbolic: true}))
	if result.Status == "error" {
		t.Fatalf("dangling symlink should succeed: %s", result.Output)
	}

	// Verify symlink exists but is dangling
	_, err := os.Lstat(link)
	if err != nil {
		t.Fatal("symlink should exist")
	}
	_, err = os.Stat(link) // follows symlink
	if err == nil {
		t.Error("expected error following dangling symlink")
	}
}

func TestLnCommand_HardLinkNonExistent(t *testing.T) {
	cmd := &LnCommand{}
	result := cmd.Execute(makeLnTask(lnArgs{Target: "/nonexistent/file", Link: "/tmp/link"}))
	if result.Status != "error" {
		t.Error("expected error for hard link to non-existent target")
	}
}

func TestLnCommand_Force(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("force test on Unix only")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")

	os.WriteFile(target, []byte("target"), 0644)
	os.Symlink(target, link) // create initial symlink

	// Create new target and force-replace
	target2 := filepath.Join(dir, "target2.txt")
	os.WriteFile(target2, []byte("new target"), 0644)

	cmd := &LnCommand{}
	result := cmd.Execute(makeLnTask(lnArgs{Target: target2, Link: link, Symbolic: true, Force: true}))
	if result.Status == "error" {
		t.Fatalf("force symlink failed: %s", result.Output)
	}

	resolved, _ := os.Readlink(link)
	if resolved != target2 {
		t.Errorf("expected '%s', got '%s'", target2, resolved)
	}
}

func TestLnCommand_ExistsWithoutForce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test on Unix only")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")

	os.WriteFile(target, []byte("content"), 0644)
	os.WriteFile(link, []byte("existing"), 0644) // link path already exists

	cmd := &LnCommand{}
	result := cmd.Execute(makeLnTask(lnArgs{Target: target, Link: link, Symbolic: true}))
	if result.Status != "error" {
		t.Error("expected error when link path exists without force")
	}
}
