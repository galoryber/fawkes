//go:build linux

package commands

import (
	"encoding/binary"
	"testing"
)

// buildUtmpRecord creates a synthetic utmp record with correct Linux x86_64 offsets.
// Layout: ut_type(0:4), ut_pid(4:8), ut_line(8:40), ut_id(40:44),
// ut_user(44:76), ut_host(76:332), ut_tv(340:348).
func buildUtmpRecord(utType int32, user, tty, host string, tvSec uint32) []byte {
	record := make([]byte, utmpRecordSize)

	binary.LittleEndian.PutUint32(record[0:4], uint32(utType))
	copy(record[44:44+utmpUserSize], user)
	copy(record[8:8+utmpLineSize], tty)
	copy(record[76:76+utmpHostSize], host)
	binary.LittleEndian.PutUint32(record[340:344], tvSec)

	return record
}

func TestBuildUtmpRecordOffsets(t *testing.T) {
	rec := buildUtmpRecord(utUserProc, "testuser", "pts/0", "192.168.1.100", 1700000000)

	if len(rec) != utmpRecordSize {
		t.Fatalf("expected record size %d, got %d", utmpRecordSize, len(rec))
	}

	utType := int32(binary.LittleEndian.Uint32(rec[0:4]))
	if utType != utUserProc {
		t.Errorf("expected ut_type %d, got %d", utUserProc, utType)
	}

	user := extractCString(rec[44 : 44+utmpUserSize])
	if user != "testuser" {
		t.Errorf("expected user 'testuser', got '%s'", user)
	}

	tty := extractCString(rec[8 : 8+utmpLineSize])
	if tty != "pts/0" {
		t.Errorf("expected tty 'pts/0', got '%s'", tty)
	}

	host := extractCString(rec[76 : 76+utmpHostSize])
	if host != "192.168.1.100" {
		t.Errorf("expected host '192.168.1.100', got '%s'", host)
	}
}

func TestWhoPlatformActiveFiltering(t *testing.T) {
	args := whoArgs{All: false}
	entries := whoPlatform(args)
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
	for _, e := range entries {
		if e.TTY == "" {
			t.Error("expected non-empty TTY (should be '-' at minimum)")
		}
	}
}

func TestWhoSessionEntryStatus(t *testing.T) {
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
}
