//go:build linux || darwin
// +build linux darwin

package commands

import (
	"os"
	"testing"
)

func TestFindFileOwnedBy_CurrentUser(t *testing.T) {
	// Create a temp file — should be owned by current UID
	f, err := os.CreateTemp(t.TempDir(), "find_test")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	uid := os.Getuid()
	if !findFileOwnedBy(info, int64(uid)) {
		t.Errorf("expected file to be owned by UID %d", uid)
	}
}

func TestFindFileOwnedBy_WrongUID(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "find_test")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	// UID 99999 should not own this file (unless test runs as that UID)
	fakeUID := int64(99999)
	if int64(os.Getuid()) == fakeUID {
		t.Skip("running as UID 99999, can't test wrong-owner case")
	}
	if findFileOwnedBy(info, fakeUID) {
		t.Errorf("file should not be owned by UID %d", fakeUID)
	}
}

func TestFindFileOwnedBy_RootOwned(t *testing.T) {
	// /etc/passwd is typically owned by root (UID 0)
	info, err := os.Stat("/etc/passwd")
	if err != nil {
		t.Skip("no /etc/passwd available")
	}
	if !findFileOwnedBy(info, 0) {
		t.Error("expected /etc/passwd to be owned by UID 0")
	}
	if findFileOwnedBy(info, 99999) {
		t.Error("/etc/passwd should not be owned by UID 99999")
	}
}
