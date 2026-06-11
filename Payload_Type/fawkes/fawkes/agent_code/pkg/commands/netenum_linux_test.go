//go:build linux

package commands

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestParseUtmp_ValidRecords(t *testing.T) {
	dir := t.TempDir()
	utmpPath := filepath.Join(dir, "utmp")

	f, err := os.Create(utmpPath)
	if err != nil {
		t.Fatal(err)
	}

	writeUtmpRecord(f, 7, "testuser", "pts/0", "192.168.1.10")
	writeUtmpRecord(f, 7, "admin", "pts/1", "10.0.0.5")
	f.Close()

	entries, err := parseUtmp(utmpPath)
	if err != nil {
		t.Fatalf("parseUtmp error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].Name != "testuser" {
		t.Errorf("entry[0].Name = %q, want %q", entries[0].Name, "testuser")
	}
	if entries[0].Source != "pts/0" {
		t.Errorf("entry[0].Source = %q, want %q", entries[0].Source, "pts/0")
	}
	if entries[0].Client != "192.168.1.10" {
		t.Errorf("entry[0].Client = %q, want %q", entries[0].Client, "192.168.1.10")
	}
	if entries[0].Type != "loggedon" {
		t.Errorf("entry[0].Type = %q, want %q", entries[0].Type, "loggedon")
	}

	if entries[1].Name != "admin" {
		t.Errorf("entry[1].Name = %q, want %q", entries[1].Name, "admin")
	}
}

func TestParseUtmp_NonUserRecords(t *testing.T) {
	dir := t.TempDir()
	utmpPath := filepath.Join(dir, "utmp")

	f, err := os.Create(utmpPath)
	if err != nil {
		t.Fatal(err)
	}

	writeUtmpRecord(f, 1, "reboot", "~", "")
	writeUtmpRecord(f, 6, "LOGIN", "tty1", "")
	writeUtmpRecord(f, 8, "", "pts/0", "")
	f.Close()

	entries, err := parseUtmp(utmpPath)
	if err != nil {
		t.Fatalf("parseUtmp error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries (non-USER_PROCESS types), got %d", len(entries))
	}
}

func TestParseUtmp_EmptyUserName(t *testing.T) {
	dir := t.TempDir()
	utmpPath := filepath.Join(dir, "utmp")

	f, err := os.Create(utmpPath)
	if err != nil {
		t.Fatal(err)
	}

	writeUtmpRecord(f, 7, "", "pts/0", "10.0.0.1")
	f.Close()

	entries, err := parseUtmp(utmpPath)
	if err != nil {
		t.Fatalf("parseUtmp error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty username, got %d", len(entries))
	}
}

func TestParseUtmp_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	utmpPath := filepath.Join(dir, "utmp")
	os.WriteFile(utmpPath, []byte{}, 0644)

	entries, err := parseUtmp(utmpPath)
	if err != nil {
		t.Fatalf("parseUtmp error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseUtmp_NonexistentFile(t *testing.T) {
	_, err := parseUtmp("/nonexistent/utmp")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseUtmp_TruncatedRecord(t *testing.T) {
	dir := t.TempDir()
	utmpPath := filepath.Join(dir, "utmp")
	os.WriteFile(utmpPath, make([]byte, 100), 0644)

	entries, err := parseUtmp(utmpPath)
	if err != nil {
		t.Fatalf("parseUtmp error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for truncated record, got %d", len(entries))
	}
}

func writeUtmpRecord(f *os.File, utType int32, user, line, host string) {
	const utmpSize = 384
	buf := make([]byte, utmpSize)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(utType))

	copy(buf[8:40], user)
	copy(buf[40:72], line)
	copy(buf[76:332], host)

	f.Write(buf)
}
