//go:build linux

package commands

import (
	"os"
	"testing"
)

// TestGetXattrEmptyValue covers the size==0 early return path in getXattr (line 45-47).
// Setting an xattr with an empty value makes Getxattr return size=0 on first call.
func TestGetXattrEmptyValue(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_emptyval_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	attrName := "user.emptyval"
	if err := setXattr(f.Name(), attrName, []byte{}); err != nil {
		t.Skipf("setXattr with empty value not supported: %v", err)
	}
	defer removeXattr(f.Name(), attrName) //nolint:errcheck

	val, err := getXattr(f.Name(), attrName)
	if err != nil {
		t.Fatalf("getXattr failed: %v", err)
	}
	if len(val) != 0 {
		t.Errorf("expected empty value, got %d bytes", len(val))
	}
}

// TestRemoveXattrNULInPath covers the BytePtrFromString error path when path
// contains a NUL byte (line 63-65 in xattr_linux.go).
func TestRemoveXattrNULInPath(t *testing.T) {
	err := removeXattr("/tmp/test\x00poisoned", "user.test")
	if err == nil {
		t.Error("expected error for path containing NUL byte")
	}
}

// TestRemoveXattrNULInName covers the BytePtrFromString error path when the
// xattr name contains a NUL byte (line 66-68 in xattr_linux.go).
func TestRemoveXattrNULInName(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_nulname_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	err = removeXattr(f.Name(), "user.test\x00injected")
	if err == nil {
		t.Error("expected error for xattr name containing NUL byte")
	}
}
