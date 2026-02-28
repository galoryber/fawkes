//go:build linux

package commands

import (
	"os"
	"os/user"
	"testing"
	"time"
)

func TestGetFileOwner_CurrentUser(t *testing.T) {
	f, err := os.CreateTemp("", "fileowner_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	owner, group := getFileOwner(f.Name())

	if owner == "" || owner == "unknown" {
		t.Error("expected non-empty owner")
	}
	if group == "" || group == "unknown" {
		t.Error("expected non-empty group")
	}

	// Should match current user
	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}
	if owner != currentUser.Username {
		t.Errorf("expected owner %q, got %q", currentUser.Username, owner)
	}
}

func TestGetFileOwner_NonexistentFile(t *testing.T) {
	owner, group := getFileOwner("/nonexistent/path/file")
	if owner != "unknown" {
		t.Errorf("expected 'unknown' owner for nonexistent file, got %q", owner)
	}
	if group != "unknown" {
		t.Errorf("expected 'unknown' group for nonexistent file, got %q", group)
	}
}

func TestGetFileOwner_Directory(t *testing.T) {
	dir, err := os.MkdirTemp("", "fileowner_dir_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	owner, group := getFileOwner(dir)
	if owner == "" || owner == "unknown" {
		t.Error("expected valid owner for directory")
	}
	if group == "" || group == "unknown" {
		t.Error("expected valid group for directory")
	}
}

func TestGetFileTimestamps_NewFile(t *testing.T) {
	f, err := os.CreateTemp("", "filetimestamp_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}

	accessTime, changeTime := getFileTimestamps(info)

	// Both times should be recent (within last minute)
	if time.Since(accessTime) > time.Minute {
		t.Errorf("access time too old: %v", accessTime)
	}
	if time.Since(changeTime) > time.Minute {
		t.Errorf("change time too old: %v", changeTime)
	}
	if accessTime.IsZero() {
		t.Error("access time should not be zero")
	}
	if changeTime.IsZero() {
		t.Error("change time should not be zero")
	}
}

func TestGetFileTimestamps_KnownAccessTime(t *testing.T) {
	f, err := os.CreateTemp("", "filetimestamp_known_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	// Set known access time
	knownAtime := time.Date(2021, 6, 15, 10, 30, 0, 0, time.UTC)
	if err := os.Chtimes(f.Name(), knownAtime, time.Now()); err != nil {
		t.Fatalf("failed to set times: %v", err)
	}

	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}

	accessTime, _ := getFileTimestamps(info)
	diff := accessTime.Sub(knownAtime)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("access time %v doesn't match set time %v (diff: %v)", accessTime, knownAtime, diff)
	}
}

func TestGetFileOwner_Symlink(t *testing.T) {
	f, err := os.CreateTemp("", "fileowner_symlink_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	linkPath := f.Name() + "_link"
	if err := os.Symlink(f.Name(), linkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}
	defer os.Remove(linkPath)

	// getFileOwner uses os.Stat which follows symlinks
	owner, group := getFileOwner(linkPath)
	if owner == "" || owner == "unknown" {
		t.Error("expected valid owner for symlinked file")
	}
	if group == "" || group == "unknown" {
		t.Error("expected valid group for symlinked file")
	}
}
