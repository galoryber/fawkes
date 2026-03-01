//go:build linux

package commands

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestGetAccessTime(t *testing.T) {
	// Create temp file
	f, err := os.CreateTemp("", "timestomp_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatalf("failed to stat temp file: %v", err)
	}

	atime := getAccessTime(f.Name(), info)

	// Access time should be recent (within the last minute)
	if time.Since(atime) > time.Minute {
		t.Errorf("access time too old: %v (expected within last minute)", atime)
	}
	if atime.IsZero() {
		t.Error("access time should not be zero")
	}
}

func TestGetPlatformTimestamps(t *testing.T) {
	f, err := os.CreateTemp("", "timestomp_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatalf("failed to stat temp file: %v", err)
	}

	output := getPlatformTimestamps(f.Name(), info)
	if output == "" {
		t.Error("expected non-empty timestamp output")
	}
	if !strings.Contains(output, "Accessed:") {
		t.Errorf("expected 'Accessed:' in output, got: %s", output)
	}
}

func TestCopyCreationTime_NoOp(t *testing.T) {
	// On Linux, copyCreationTime is a no-op
	err := copyCreationTime("/tmp/target", "/tmp/source")
	if err != nil {
		t.Errorf("expected nil error for no-op copyCreationTime, got: %v", err)
	}
}

func TestSetCreationTime_NoOp(t *testing.T) {
	// On Linux, setCreationTime is a no-op
	err := setCreationTime("/tmp/target", time.Now())
	if err != nil {
		t.Errorf("expected nil error for no-op setCreationTime, got: %v", err)
	}
}

func TestGetAccessTime_ModifiedFile(t *testing.T) {
	f, err := os.CreateTemp("", "timestomp_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())

	// Write some data to modify the file
	if _, err := f.WriteString("test data"); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	f.Close()

	// Set a known access time
	knownTime := time.Date(2020, 1, 15, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(f.Name(), knownTime, time.Now()); err != nil {
		t.Fatalf("failed to set times: %v", err)
	}

	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}

	atime := getAccessTime(f.Name(), info)
	// Allow 1 second tolerance
	diff := atime.Sub(knownTime)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("access time %v doesn't match set time %v (diff: %v)", atime, knownTime, diff)
	}
}
