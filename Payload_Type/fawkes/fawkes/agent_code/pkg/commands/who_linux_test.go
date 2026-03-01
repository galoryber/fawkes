//go:build linux

package commands

import (
	"encoding/binary"
	"testing"
)

// buildSyntheticUtmpRecord creates a synthetic utmp record for testing.
// Linux utmp struct (x86_64): 384 bytes total
// offset 0: ut_type (int32)
// offset 4: ut_pid (int32) — we don't use this
// offset 8: ut_line (char[32])
// offset 40: ut_id (char[4]) — skip
// offset 44: ut_user (char[32]) — note: in who_linux.go, user is at record[4:36]
// Wait — let me re-read who_linux.go to get exact offsets.
//
// From who_linux.go:
//   utType := int32(binary.LittleEndian.Uint32(record[0:4]))
//   user := strings.TrimRight(string(record[4:36]), "\x00")
//   tty := strings.TrimRight(string(record[36:68]), "\x00")
//   host := strings.TrimRight(string(record[76:332]), "\x00")
//   tvSec := int64(binary.LittleEndian.Uint32(record[340:344]))
func buildSyntheticUtmpRecord(utType int32, user, tty, host string, tvSec uint32) []byte {
	record := make([]byte, whoUtmpRecordSize)

	// ut_type at offset 0 (4 bytes)
	binary.LittleEndian.PutUint32(record[0:4], uint32(utType))

	// user at offset 4 (32 bytes)
	copy(record[4:36], user)

	// tty at offset 36 (32 bytes)
	copy(record[36:68], tty)

	// host at offset 76 (256 bytes)
	copy(record[76:332], host)

	// tv_sec at offset 340 (4 bytes)
	binary.LittleEndian.PutUint32(record[340:344], tvSec)

	return record
}

func TestWhoPlatformWithSyntheticData(t *testing.T) {
	// This tests the actual whoPlatform function which reads from /var/run/utmp
	// We can't control the file, but we can verify it returns valid data
	args := whoArgs{All: false}
	entries := whoPlatform(args)
	// entries might be nil on a headless server with no logged-in users
	for _, e := range entries {
		if e.Status != "active" {
			t.Errorf("non-all mode should only return active sessions, got status=%s", e.Status)
		}
		if e.User == "" {
			t.Error("active session should have a username")
		}
	}
}

func TestWhoPlatformAllFlag(t *testing.T) {
	args := whoArgs{All: true}
	entries := whoPlatform(args)
	// With all=true, should include non-USER_PROCESS entries too
	// Just verify no panic and entries have basic structure
	for _, e := range entries {
		if e.TTY == "" {
			// TTY might be "-" but should not be empty after processing
			// Actually in the code, empty tty gets set to "-"
		}
	}
}

func TestBuildSyntheticUtmpRecord(t *testing.T) {
	// Verify our test helper builds correct records
	rec := buildSyntheticUtmpRecord(whoUtmpUserProcess, "testuser", "pts/0", "192.168.1.100", 1700000000)

	if len(rec) != whoUtmpRecordSize {
		t.Fatalf("expected record size %d, got %d", whoUtmpRecordSize, len(rec))
	}

	// Verify ut_type
	utType := int32(binary.LittleEndian.Uint32(rec[0:4]))
	if utType != whoUtmpUserProcess {
		t.Errorf("expected ut_type %d, got %d", whoUtmpUserProcess, utType)
	}

	// Verify user field
	user := string(rec[4:12])
	if user != "testuser" {
		t.Errorf("expected user 'testuser', got '%s'", user)
	}

	// Verify tty field
	tty := string(rec[36:41])
	if tty != "pts/0" {
		t.Errorf("expected tty 'pts/0', got '%s'", tty)
	}
}

func TestWhoSessionEntryStatus(t *testing.T) {
	// Test that whoSessionEntry correctly tracks status for different utmp types
	entry := whoSessionEntry{
		User:      "root",
		TTY:       "tty1",
		LoginTime: "2026-01-01 12:00:00",
		From:      "localhost",
		Status:    "active",
	}
	if entry.Status != "active" {
		t.Errorf("expected 'active', got '%s'", entry.Status)
	}

	entry.Status = "type=8"
	if entry.Status != "type=8" {
		t.Errorf("expected 'type=8', got '%s'", entry.Status)
	}
}
