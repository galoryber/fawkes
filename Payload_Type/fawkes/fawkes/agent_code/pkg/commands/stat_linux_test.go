//go:build linux

package commands

import (
	"os"
	"strings"
	"testing"
)

func TestStatPlatformInfo(t *testing.T) {
	// Create a temp file to stat
	tmpFile, err := os.CreateTemp("", "stat-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	info, err := os.Stat(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	statPlatformInfo(&sb, info, tmpFile.Name())
	output := sb.String()

	if output == "" {
		t.Error("expected non-empty stat output")
	}
	if !strings.Contains(output, "Inode:") {
		t.Error("expected 'Inode:' in output")
	}
	if !strings.Contains(output, "Owner:") {
		t.Error("expected 'Owner:' in output")
	}
	if !strings.Contains(output, "Group:") {
		t.Error("expected 'Group:' in output")
	}
	if !strings.Contains(output, "Access:") {
		t.Error("expected 'Access:' time in output")
	}
	if !strings.Contains(output, "Change:") {
		t.Error("expected 'Change:' time in output")
	}
	if !strings.Contains(output, "Links:") {
		t.Error("expected 'Links:' in output")
	}
}

func TestStatPlatformInfo_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	info, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	statPlatformInfo(&sb, info, tmpDir)
	output := sb.String()

	if output == "" {
		t.Error("expected non-empty stat output for directory")
	}
	if !strings.Contains(output, "Inode:") {
		t.Error("expected 'Inode:' in directory stat output")
	}
}
