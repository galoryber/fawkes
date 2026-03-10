//go:build darwin

package commands

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildSyntheticUtmpxRecord creates a synthetic macOS utmpx record for testing.
// macOS utmpx: 628 bytes total.
func buildSyntheticUtmpxRecord(utType int16, user, tty, host string, tvSec uint32) []byte {
	rec := make([]byte, whoUtmpxRecordSize)
	copy(rec[0:256], user)                                           // ut_user
	copy(rec[260:292], tty)                                          // ut_line
	binary.LittleEndian.PutUint16(rec[296:298], uint16(utType))      // ut_type
	binary.LittleEndian.PutUint32(rec[300:304], tvSec)               // tv_sec
	copy(rec[308:564], host)                                         // ut_host
	return rec
}

func writeTestUtmpx(t *testing.T, records [][]byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "utmpx")
	var data []byte
	for _, r := range records {
		data = append(data, r...)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWhoDarwinNativeBasic(t *testing.T) {
	path := writeTestUtmpx(t, [][]byte{
		buildSyntheticUtmpxRecord(10, "utmpx-1.00", "", "", 0),       // header
		buildSyntheticUtmpxRecord(7, "gary", "ttys000", "", 1700000000),
		buildSyntheticUtmpxRecord(7, "root", "ttys001", "", 1700000000),
		buildSyntheticUtmpxRecord(8, "dead", "ttys002", "", 1700000000), // DEAD_PROCESS
	})

	origPath := whoUtmpxPath
	whoUtmpxPath = path
	defer func() { whoUtmpxPath = origPath }()

	entries := whoPlatform(whoArgs{All: false})
	if len(entries) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(entries))
	}
	if entries[0].User != "gary" {
		t.Errorf("entries[0].User = %q, want gary", entries[0].User)
	}
	if entries[0].TTY != "ttys000" {
		t.Errorf("entries[0].TTY = %q, want ttys000", entries[0].TTY)
	}
	if entries[0].Status != "active" {
		t.Errorf("entries[0].Status = %q, want active", entries[0].Status)
	}
	if entries[1].User != "root" {
		t.Errorf("entries[1].User = %q, want root", entries[1].User)
	}
}

func TestWhoDarwinNativeAllFlag(t *testing.T) {
	path := writeTestUtmpx(t, [][]byte{
		buildSyntheticUtmpxRecord(10, "utmpx-1.00", "", "", 0),       // header
		buildSyntheticUtmpxRecord(7, "gary", "ttys000", "", 1700000000),
		buildSyntheticUtmpxRecord(8, "dead", "ttys001", "", 1700000000),
	})

	origPath := whoUtmpxPath
	whoUtmpxPath = path
	defer func() { whoUtmpxPath = origPath }()

	entries := whoPlatform(whoArgs{All: true})
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (all=true), got %d", len(entries))
	}
	// Header should have type=10 status
	if entries[0].Status != "type=10" {
		t.Errorf("header status = %q, want type=10", entries[0].Status)
	}
	// Active user
	if entries[1].Status != "active" {
		t.Errorf("user status = %q, want active", entries[1].Status)
	}
	// Dead process
	if entries[2].Status != "type=8" {
		t.Errorf("dead status = %q, want type=8", entries[2].Status)
	}
}

func TestWhoDarwinNativeWithHost(t *testing.T) {
	path := writeTestUtmpx(t, [][]byte{
		buildSyntheticUtmpxRecord(7, "remote", "ttys000", "192.168.1.100", 1700000000),
	})

	origPath := whoUtmpxPath
	whoUtmpxPath = path
	defer func() { whoUtmpxPath = origPath }()

	entries := whoPlatform(whoArgs{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].From != "192.168.1.100" {
		t.Errorf("From = %q, want 192.168.1.100", entries[0].From)
	}
}

func TestWhoDarwinNativeEmptyHost(t *testing.T) {
	path := writeTestUtmpx(t, [][]byte{
		buildSyntheticUtmpxRecord(7, "local", "ttys000", "", 1700000000),
	})

	origPath := whoUtmpxPath
	whoUtmpxPath = path
	defer func() { whoUtmpxPath = origPath }()

	entries := whoPlatform(whoArgs{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].From != "-" {
		t.Errorf("From = %q, want -", entries[0].From)
	}
}

func TestWhoDarwinNativeEmptyFile(t *testing.T) {
	path := writeTestUtmpx(t, nil)

	origPath := whoUtmpxPath
	whoUtmpxPath = path
	defer func() { whoUtmpxPath = origPath }()

	entries := whoPlatform(whoArgs{})
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty file, got %d", len(entries))
	}
}

func TestWhoDarwinNativeMissingFile(t *testing.T) {
	origPath := whoUtmpxPath
	whoUtmpxPath = "/nonexistent/utmpx"
	defer func() { whoUtmpxPath = origPath }()

	entries := whoPlatform(whoArgs{})
	if entries != nil {
		t.Errorf("expected nil for missing file, got %d entries", len(entries))
	}
}

func TestWhoDarwinNativeLoginTime(t *testing.T) {
	path := writeTestUtmpx(t, [][]byte{
		buildSyntheticUtmpxRecord(7, "user1", "ttys000", "", 1700000000),
	})

	origPath := whoUtmpxPath
	whoUtmpxPath = path
	defer func() { whoUtmpxPath = origPath }()

	entries := whoPlatform(whoArgs{})
	if len(entries) != 1 {
		t.Fatal("expected 1 entry")
	}
	if entries[0].LoginTime == "" {
		t.Error("LoginTime should not be empty")
	}
	// 1700000000 = 2023-11-14 in UTC
	if len(entries[0].LoginTime) < 10 {
		t.Errorf("LoginTime too short: %q", entries[0].LoginTime)
	}
}

func TestWhoDarwinNativeEmptyUser(t *testing.T) {
	path := writeTestUtmpx(t, [][]byte{
		buildSyntheticUtmpxRecord(7, "", "ttys000", "", 1700000000),
	})

	origPath := whoUtmpxPath
	whoUtmpxPath = path
	defer func() { whoUtmpxPath = origPath }()

	// Without all flag, empty users should be skipped
	entries := whoPlatform(whoArgs{All: false})
	if len(entries) != 0 {
		t.Errorf("expected 0 entries (empty user filtered), got %d", len(entries))
	}

	// With all flag, empty users should be included
	entries = whoPlatform(whoArgs{All: true})
	if len(entries) != 1 {
		t.Errorf("expected 1 entry (all=true), got %d", len(entries))
	}
}
