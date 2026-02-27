package commands

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestChownName(t *testing.T) {
	c := &ChownCommand{}
	if c.Name() != "chown" {
		t.Errorf("expected 'chown', got '%s'", c.Name())
	}
}

func TestChownDescription(t *testing.T) {
	c := &ChownCommand{}
	if c.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestChownEmptyParams(t *testing.T) {
	c := &ChownCommand{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestChownBadJSON(t *testing.T) {
	c := &ChownCommand{}
	result := c.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestChownMissingPath(t *testing.T) {
	c := &ChownCommand{}
	params, _ := json.Marshal(chownArgs{Owner: "root"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "path") {
		t.Error("error should mention path")
	}
}

func TestChownMissingOwnerAndGroup(t *testing.T) {
	c := &ChownCommand{}
	params, _ := json.Marshal(chownArgs{Path: "/tmp/test"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "owner or group") {
		t.Error("error should mention owner or group")
	}
}

func TestChownWindowsUnsupported(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}
	c := &ChownCommand{}
	params, _ := json.Marshal(chownArgs{Path: "C:\\test", Owner: "Administrator"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error on Windows, got %s", result.Status)
	}
}

func TestChownNonexistentFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on Windows")
	}
	c := &ChownCommand{}
	params, _ := json.Marshal(chownArgs{Path: "/nonexistent/file", Owner: "root"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestChownInvalidUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on Windows")
	}

	f, err := os.CreateTemp("", "chown_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	c := &ChownCommand{}
	params, _ := json.Marshal(chownArgs{Path: f.Name(), Owner: "nonexistent_user_xyz_12345"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid user, got %s", result.Status)
	}
}

func TestChownCurrentUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on Windows")
	}

	// Get current user
	u, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	f, err := os.CreateTemp("", "chown_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	c := &ChownCommand{}
	// Chown to ourselves (should always succeed without root)
	params, _ := json.Marshal(chownArgs{Path: f.Name(), Owner: u.Username})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	if !strings.Contains(result.Output, u.Username) {
		t.Errorf("output should contain username '%s'", u.Username)
	}
}

func TestChownByUID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on Windows")
	}

	u, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	f, err := os.CreateTemp("", "chown_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	c := &ChownCommand{}
	params, _ := json.Marshal(chownArgs{Path: f.Name(), Owner: u.Uid})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestChownRecursive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on Windows")
	}

	u, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	dir, err := os.MkdirTemp("", "chown_test_dir_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Create files
	for i := 0; i < 3; i++ {
		f, err := os.CreateTemp(dir, "file*")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	subdir := filepath.Join(dir, "subdir")
	os.Mkdir(subdir, 0755)

	c := &ChownCommand{}
	params, _ := json.Marshal(chownArgs{Path: dir, Owner: u.Username, Recursive: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	if !strings.Contains(result.Output, "items changed") {
		t.Error("output should mention items changed")
	}
}

func TestChownResolveUID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on Windows")
	}

	// Test numeric UID
	uid, err := chownResolveUID("0")
	if err != nil {
		t.Errorf("failed to resolve UID 0: %v", err)
	}
	if uid != 0 {
		t.Errorf("expected UID 0, got %d", uid)
	}

	// Test username resolution
	u, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}
	uid, err = chownResolveUID(u.Username)
	if err != nil {
		t.Errorf("failed to resolve username '%s': %v", u.Username, err)
	}
	if uid < 0 {
		t.Errorf("expected positive UID, got %d", uid)
	}
}

func TestChownResolveGID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on Windows")
	}

	// Test numeric GID
	gid, err := chownResolveGID("0")
	if err != nil {
		t.Errorf("failed to resolve GID 0: %v", err)
	}
	if gid != 0 {
		t.Errorf("expected GID 0, got %d", gid)
	}
}

func TestChownFormatOwnership(t *testing.T) {
	result := chownFormatOwnership("gary", "staff", 1000, 50)
	if !strings.Contains(result, "gary") || !strings.Contains(result, "staff") {
		t.Errorf("expected owner and group in output, got '%s'", result)
	}
	if !strings.Contains(result, "uid=1000") || !strings.Contains(result, "gid=50") {
		t.Errorf("expected uid/gid in output, got '%s'", result)
	}
}

func TestChownGroupOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on Windows")
	}

	u, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}

	f, err := os.CreateTemp("", "chown_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	c := &ChownCommand{}
	// Change group only (use current user's primary group)
	params, _ := json.Marshal(chownArgs{Path: f.Name(), Group: u.Gid})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
}
