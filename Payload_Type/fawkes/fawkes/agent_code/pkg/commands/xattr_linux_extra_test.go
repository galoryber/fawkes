//go:build linux

package commands

import (
	"os"
	"strings"
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

// TestXattrGetHex covers the args.Hex==true branch in xattrGet (hex.Dump output).
func TestXattrGetHex(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_gethex_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	if err := setXattr(f.Name(), "user.hexdata", []byte{0xDE, 0xAD, 0xBE, 0xEF}); err != nil {
		t.Skipf("setXattr not supported: %v", err)
	}
	defer removeXattr(f.Name(), "user.hexdata") //nolint:errcheck

	result := xattrGet(xattrArgs{Path: f.Name(), Name: "user.hexdata", Hex: true})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "de ad be ef") {
		t.Errorf("expected hex dump with 'de ad be ef', got: %s", result.Output)
	}
}

// TestXattrSetError covers the setXattr error path in xattrSet — triggered by a
// NUL byte in the attribute name, which causes syscall.BytePtrFromString to fail.
func TestXattrSetError(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_seterr_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	result := xattrSet(xattrArgs{
		Path:  f.Name(),
		Name:  "user.test\x00bad",
		Value: "value",
	})
	if result.Status != "error" {
		t.Errorf("expected error for NUL byte in xattr name, got %q: %s", result.Status, result.Output)
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
