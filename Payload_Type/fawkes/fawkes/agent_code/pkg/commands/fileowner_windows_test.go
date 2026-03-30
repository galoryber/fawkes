//go:build windows

package commands

import (
	"os"
	"testing"
)

func TestGetFileOwner_CurrentDir(t *testing.T) {
	// Test with a known-existing path
	owner, group := getFileOwner(".")
	if owner == "" {
		t.Error("owner is empty for current directory")
	}
	if group == "" {
		t.Error("group is empty for current directory")
	}
}

func TestGetFileOwner_NonExistent(t *testing.T) {
	owner, group := getFileOwner(`C:\this\path\does\not\exist\at\all`)
	// Should return "unknown" for non-existent paths
	if owner != "unknown" {
		t.Errorf("owner = %q, want unknown for non-existent path", owner)
	}
	if group != "unknown" {
		t.Errorf("group = %q, want unknown for non-existent path", group)
	}
}

func TestGetFileTimestamps_TempFile(t *testing.T) {
	f, err := os.CreateTemp("", "fawkes_test_*")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	accessTime, creationTime := getFileTimestamps(info)
	if accessTime.IsZero() {
		t.Error("accessTime is zero")
	}
	if creationTime.IsZero() {
		t.Error("creationTime is zero")
	}
}
