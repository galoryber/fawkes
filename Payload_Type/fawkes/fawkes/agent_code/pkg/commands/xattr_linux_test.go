//go:build linux

package commands

import (
	"bytes"
	"os"
	"testing"
)

func TestXattr_SetGetRemove(t *testing.T) {
	// Create temp file
	f, err := os.CreateTemp("", "xattr_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	attrName := "user.test_attribute"
	attrValue := []byte("test_value_123")

	// Set xattr
	if err := setXattr(f.Name(), attrName, attrValue); err != nil {
		t.Skipf("setXattr failed (filesystem may not support xattrs): %v", err)
	}

	// Get xattr
	got, err := getXattr(f.Name(), attrName)
	if err != nil {
		t.Fatalf("getXattr failed: %v", err)
	}
	if !bytes.Equal(got, attrValue) {
		t.Errorf("expected value %q, got %q", attrValue, got)
	}

	// List xattrs — should contain our attribute
	attrs, err := listXattr(f.Name())
	if err != nil {
		t.Fatalf("listXattr failed: %v", err)
	}
	found := false
	for _, a := range attrs {
		if a == attrName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in xattr list, got %v", attrName, attrs)
	}

	// Remove xattr
	if err := removeXattr(f.Name(), attrName); err != nil {
		t.Fatalf("removeXattr failed: %v", err)
	}

	// Verify removal
	attrsAfter, err := listXattr(f.Name())
	if err != nil {
		t.Fatalf("listXattr after remove failed: %v", err)
	}
	for _, a := range attrsAfter {
		if a == attrName {
			t.Error("xattr should have been removed")
		}
	}
}

func TestListXattr_NoAttributes(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_empty_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	attrs, err := listXattr(f.Name())
	if err != nil {
		t.Skipf("listXattr failed (may not support xattrs): %v", err)
	}
	if len(attrs) != 0 {
		t.Errorf("expected no xattrs on fresh file, got %v", attrs)
	}
}

func TestGetXattr_NonExistent(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_noattr_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	_, err = getXattr(f.Name(), "user.nonexistent")
	if err == nil {
		t.Error("expected error for non-existent xattr")
	}
}

func TestSetXattr_BinaryData(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_binary_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	attrName := "user.binary_test"
	attrValue := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}

	if err := setXattr(f.Name(), attrName, attrValue); err != nil {
		t.Skipf("setXattr failed: %v", err)
	}

	got, err := getXattr(f.Name(), attrName)
	if err != nil {
		t.Fatalf("getXattr failed: %v", err)
	}
	if !bytes.Equal(got, attrValue) {
		t.Errorf("binary data mismatch: expected %x, got %x", attrValue, got)
	}

	// Cleanup
	_ = removeXattr(f.Name(), attrName)
}

func TestSetXattr_MultipleAttributes(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_multi_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	attrs := map[string][]byte{
		"user.attr1": []byte("value1"),
		"user.attr2": []byte("value2"),
		"user.attr3": []byte("value3"),
	}

	for name, val := range attrs {
		if err := setXattr(f.Name(), name, val); err != nil {
			t.Skipf("setXattr failed: %v", err)
		}
	}

	listed, err := listXattr(f.Name())
	if err != nil {
		t.Fatalf("listXattr failed: %v", err)
	}
	if len(listed) != 3 {
		t.Errorf("expected 3 xattrs, got %d: %v", len(listed), listed)
	}

	// Verify each value
	for name, expected := range attrs {
		got, err := getXattr(f.Name(), name)
		if err != nil {
			t.Errorf("getXattr(%q) failed: %v", name, err)
			continue
		}
		if !bytes.Equal(got, expected) {
			t.Errorf("getXattr(%q): expected %q, got %q", name, expected, got)
		}
	}

	// Cleanup
	for name := range attrs {
		_ = removeXattr(f.Name(), name)
	}
}

func TestRemoveXattr_NonExistent(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_remove_noexist_test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	err = removeXattr(f.Name(), "user.nonexistent")
	if err == nil {
		t.Error("expected error when removing non-existent xattr")
	}
}

func TestXattr_InvalidPath(t *testing.T) {
	_, err := listXattr("/nonexistent/path/file")
	if err == nil {
		t.Error("expected error for invalid path")
	}

	_, err = getXattr("/nonexistent/path/file", "user.test")
	if err == nil {
		t.Error("expected error for invalid path")
	}

	err = setXattr("/nonexistent/path/file", "user.test", []byte("val"))
	if err == nil {
		t.Error("expected error for invalid path")
	}
}
