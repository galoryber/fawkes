//go:build linux

package commands

import (
	"os"
	"strings"
	"testing"
)

func TestFileAttrCommand_GetAttrs(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fileattr-test-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	cmd := &FileAttrCommand{}
	result := cmd.Execute(makeFileAttrTask(fileAttrArgs{Path: f.Name()}))

	// Getting attrs may fail on filesystems that don't support ioctl (like tmpfs)
	// Accept either success or specific error
	if result.Status == "error" {
		if !strings.Contains(result.Output, "filesystem may not support it") {
			t.Fatalf("unexpected error: %s", result.Output)
		}
		t.Skip("filesystem does not support ext attributes")
	}

	if !strings.Contains(result.Output, "File attributes for") {
		t.Errorf("expected attribute header, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Raw flags") {
		t.Errorf("expected raw flags, got: %s", result.Output)
	}
}

func TestFileAttrCommand_SetInvalidAttr(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fileattr-test-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	cmd := &FileAttrCommand{}
	result := cmd.Execute(makeFileAttrTask(fileAttrArgs{Path: f.Name(), Attrs: "badformat"}))
	if result.Status != "error" {
		t.Error("expected error for attribute without +/- prefix")
	}
}
