//go:build darwin

package commands

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestLogonSessionsCommandName(t *testing.T) {
	cmd := &LogonSessionsCommand{}
	if cmd.Name() != "logonsessions" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "logonsessions")
	}
}

func TestLogonSessionsCommandDescription(t *testing.T) {
	cmd := &LogonSessionsCommand{}
	desc := cmd.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}
	if !strings.Contains(desc, "T1033") {
		t.Error("Description should mention T1033")
	}
}

func TestLogonSessionsInvalidJSON(t *testing.T) {
	cmd := &LogonSessionsCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestLogonSessionsUnknownAction(t *testing.T) {
	cmd := &LogonSessionsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' in output, got: %s", result.Output)
	}
}

func TestLogonSessionsDefaultAction(t *testing.T) {
	cmd := &LogonSessionsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Logf("Output: %s", result.Output)
		// May fail if utmpx not readable, which is acceptable
	}
}

// buildTestUtmpxData creates a synthetic macOS utmpx binary file for testing.
func buildTestUtmpxData(entries []utmpxEntry) []byte {
	var data []byte
	for _, e := range entries {
		rec := make([]byte, utmpxRecordSize)

		// ut_user (offset 0, 256 bytes)
		copy(rec[utmpxOffsetUser:utmpxOffsetUser+utmpxUserSize], e.User)

		// ut_id (offset 256, 4 bytes)
		copy(rec[utmpxOffsetID:utmpxOffsetID+utmpxIDSize], e.ID)

		// ut_line (offset 260, 32 bytes)
		copy(rec[utmpxOffsetLine:utmpxOffsetLine+utmpxLineSize], e.Line)

		// ut_pid (offset 292, 4 bytes)
		binary.LittleEndian.PutUint32(rec[utmpxOffsetPID:utmpxOffsetPID+4], uint32(e.PID))

		// ut_type (offset 296, 2 bytes)
		binary.LittleEndian.PutUint16(rec[utmpxOffsetType:utmpxOffsetType+2], uint16(e.Type))

		// ut_tv.tv_sec (offset 300, 4 bytes)
		binary.LittleEndian.PutUint32(rec[utmpxOffsetSec:utmpxOffsetSec+4], uint32(e.TimeSec))

		// ut_host (offset 308, 256 bytes)
		copy(rec[utmpxOffsetHost:utmpxOffsetHost+utmpxHostSize], e.Host)

		data = append(data, rec...)
	}
	return data
}

func TestParseUtmpxForLogonSessions(t *testing.T) {
	now := time.Now()
	testEntries := []utmpxEntry{
		{
			Type:    10, // SIGNATURE (header record)
			User:    "utmpx-1.00",
			TimeSec: 0,
		},
		{
			Type:    7, // USER_PROCESS
			PID:     1234,
			Line:    "ttys000",
			ID:      "s000",
			User:    "gary",
			Host:    "",
			TimeSec: int32(now.Unix()),
		},
		{
			Type: 8, // DEAD_PROCESS
			PID:  5678,
			Line: "ttys001",
			User: "",
		},
	}

	data := buildTestUtmpxData(testEntries)

	tmpDir := t.TempDir()
	utmpxPath := filepath.Join(tmpDir, "utmpx")
	if err := os.WriteFile(utmpxPath, data, 0644); err != nil {
		t.Fatalf("failed to write test utmpx: %v", err)
	}

	origPath := logonSessionsUtmpxPath
	logonSessionsUtmpxPath = utmpxPath
	defer func() { logonSessionsUtmpxPath = origPath }()

	entries, err := parseUtmpxForLogonSessions()
	if err != nil {
		t.Fatalf("parseUtmpxForLogonSessions() error: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Header record
	if entries[0].Type != 10 {
		t.Errorf("entries[0].Type = %d, want 10 (SIGNATURE)", entries[0].Type)
	}

	// User session
	if entries[1].User != "gary" {
		t.Errorf("entries[1].User = %q, want gary", entries[1].User)
	}
	if entries[1].Line != "ttys000" {
		t.Errorf("entries[1].Line = %q, want ttys000", entries[1].Line)
	}
	if entries[1].PID != 1234 {
		t.Errorf("entries[1].PID = %d, want 1234", entries[1].PID)
	}
}

func TestEnumerateDarwinSessions(t *testing.T) {
	now := time.Now()
	testEntries := []utmpxEntry{
		{Type: 10, User: "utmpx-1.00"}, // header — filtered
		{Type: 7, PID: 100, Line: "ttys000", User: "alice", TimeSec: int32(now.Unix())},
		{Type: 8, PID: 200, Line: "ttys001", User: "dead"},                            // DEAD — filtered
		{Type: 7, PID: 300, Line: "ttys002", User: "bob", TimeSec: int32(now.Unix())}, // active
		{Type: 7, PID: 400, Line: "ttys003", User: "", TimeSec: int32(now.Unix())},    // empty user — filtered
	}

	data := buildTestUtmpxData(testEntries)
	tmpDir := t.TempDir()
	utmpxPath := filepath.Join(tmpDir, "utmpx")
	if err := os.WriteFile(utmpxPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPath := logonSessionsUtmpxPath
	logonSessionsUtmpxPath = utmpxPath
	defer func() { logonSessionsUtmpxPath = origPath }()

	sessions, err := enumerateDarwinSessions()
	if err != nil {
		t.Fatalf("enumerateDarwinSessions() error: %v", err)
	}

	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	if sessions[0].UserName != "alice" {
		t.Errorf("sessions[0].UserName = %q, want alice", sessions[0].UserName)
	}
	if sessions[0].Station != "ttys000" {
		t.Errorf("sessions[0].Station = %q, want ttys000", sessions[0].Station)
	}
	if sessions[0].State != "Active" {
		t.Errorf("sessions[0].State = %q, want Active", sessions[0].State)
	}

	if sessions[1].UserName != "bob" {
		t.Errorf("sessions[1].UserName = %q, want bob", sessions[1].UserName)
	}
}

func TestLogonSessionsListJSON(t *testing.T) {
	now := time.Now()
	testEntries := []utmpxEntry{
		{Type: 7, PID: 100, Line: "ttys000", User: "gary", TimeSec: int32(now.Unix())},
		{Type: 7, PID: 200, Line: "ttys001", User: "root", TimeSec: int32(now.Unix())},
	}

	data := buildTestUtmpxData(testEntries)
	tmpDir := t.TempDir()
	utmpxPath := filepath.Join(tmpDir, "utmpx")
	if err := os.WriteFile(utmpxPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPath := logonSessionsUtmpxPath
	logonSessionsUtmpxPath = utmpxPath
	defer func() { logonSessionsUtmpxPath = origPath }()

	result := logonSessionsList(logonSessionsArgs{Action: "list"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	var entries []sessionEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, result.Output)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestLogonSessionsListFilter(t *testing.T) {
	now := time.Now()
	testEntries := []utmpxEntry{
		{Type: 7, PID: 100, Line: "ttys000", User: "gary", TimeSec: int32(now.Unix())},
		{Type: 7, PID: 200, Line: "ttys001", User: "root", TimeSec: int32(now.Unix())},
		{Type: 7, PID: 300, Line: "ttys002", User: "gary", TimeSec: int32(now.Unix())},
	}

	data := buildTestUtmpxData(testEntries)
	tmpDir := t.TempDir()
	utmpxPath := filepath.Join(tmpDir, "utmpx")
	if err := os.WriteFile(utmpxPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPath := logonSessionsUtmpxPath
	logonSessionsUtmpxPath = utmpxPath
	defer func() { logonSessionsUtmpxPath = origPath }()

	result := logonSessionsList(logonSessionsArgs{Action: "list", Filter: "gary"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	var entries []sessionEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 filtered entries (gary), got %d", len(entries))
	}
	for _, e := range entries {
		if e.UserName != "gary" {
			t.Errorf("filtered entry has user %q, want gary", e.UserName)
		}
	}
}

func TestLogonSessionsUsersAction(t *testing.T) {
	now := time.Now()
	testEntries := []utmpxEntry{
		{Type: 7, PID: 100, Line: "ttys000", User: "gary", TimeSec: int32(now.Unix())},
		{Type: 7, PID: 200, Line: "ttys001", User: "gary", TimeSec: int32(now.Unix())},
		{Type: 7, PID: 300, Line: "ttys002", User: "root", TimeSec: int32(now.Unix())},
	}

	data := buildTestUtmpxData(testEntries)
	tmpDir := t.TempDir()
	utmpxPath := filepath.Join(tmpDir, "utmpx")
	if err := os.WriteFile(utmpxPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPath := logonSessionsUtmpxPath
	logonSessionsUtmpxPath = utmpxPath
	defer func() { logonSessionsUtmpxPath = origPath }()

	result := logonSessionsUsers(logonSessionsArgs{Action: "users"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	var entries []userEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("invalid JSON: %v\nOutput: %s", err, result.Output)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 unique users, got %d", len(entries))
	}

	var garyEntry *userEntry
	for i := range entries {
		if entries[i].User == "gary" {
			garyEntry = &entries[i]
			break
		}
	}
	if garyEntry == nil {
		t.Fatal("gary not found in users output")
	}
	if garyEntry.Sessions != 2 {
		t.Errorf("gary.Sessions = %d, want 2", garyEntry.Sessions)
	}
}

func TestLogonSessionsEmptyUtmpx(t *testing.T) {
	tmpDir := t.TempDir()
	utmpxPath := filepath.Join(tmpDir, "utmpx")
	if err := os.WriteFile(utmpxPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	origPath := logonSessionsUtmpxPath
	logonSessionsUtmpxPath = utmpxPath
	defer func() { logonSessionsUtmpxPath = origPath }()

	result := logonSessionsList(logonSessionsArgs{Action: "list"})
	if result.Status != "success" {
		t.Fatalf("expected success for empty utmpx, got %s: %s", result.Status, result.Output)
	}
	if result.Output != "[]" {
		t.Errorf("expected empty array, got: %s", result.Output)
	}
}

func TestLogonSessionsNoUtmpxFile(t *testing.T) {
	origPath := logonSessionsUtmpxPath
	logonSessionsUtmpxPath = "/nonexistent/path/utmpx"
	defer func() { logonSessionsUtmpxPath = origPath }()

	result := logonSessionsList(logonSessionsArgs{Action: "list"})
	if result.Status != "error" {
		t.Errorf("expected error for missing utmpx, got %s", result.Status)
	}
}

func TestLogonSessionsLoginTime(t *testing.T) {
	ts := int32(1700000000) // 2023-11-14 22:13:20 UTC
	testEntries := []utmpxEntry{
		{Type: 7, PID: 100, Line: "ttys000", User: "user1", TimeSec: ts},
	}

	data := buildTestUtmpxData(testEntries)
	tmpDir := t.TempDir()
	utmpxPath := filepath.Join(tmpDir, "utmpx")
	if err := os.WriteFile(utmpxPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPath := logonSessionsUtmpxPath
	logonSessionsUtmpxPath = utmpxPath
	defer func() { logonSessionsUtmpxPath = origPath }()

	sessions, err := enumerateDarwinSessions()
	if err != nil {
		t.Fatal(err)
	}

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	if sessions[0].LoginTime == "" {
		t.Error("LoginTime should be set")
	}
	if !strings.Contains(sessions[0].LoginTime, "2023-11-14") {
		t.Errorf("LoginTime = %q, expected to contain 2023-11-14", sessions[0].LoginTime)
	}
}

func TestLogonSessionsWithRemoteHost(t *testing.T) {
	testEntries := []utmpxEntry{
		{
			Type:    7,
			PID:     100,
			Line:    "ttys000",
			User:    "remote_user",
			Host:    "workstation.corp.local",
			TimeSec: int32(time.Now().Unix()),
		},
	}

	data := buildTestUtmpxData(testEntries)
	tmpDir := t.TempDir()
	utmpxPath := filepath.Join(tmpDir, "utmpx")
	if err := os.WriteFile(utmpxPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPath := logonSessionsUtmpxPath
	logonSessionsUtmpxPath = utmpxPath
	defer func() { logonSessionsUtmpxPath = origPath }()

	sessions, err := enumerateDarwinSessions()
	if err != nil {
		t.Fatal(err)
	}

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].ClientName != "workstation.corp.local" {
		t.Errorf("ClientName = %q, want workstation.corp.local", sessions[0].ClientName)
	}
}

func TestLogonSessionsViaExecute(t *testing.T) {
	now := time.Now()
	testEntries := []utmpxEntry{
		{Type: 7, PID: 100, Line: "ttys000", User: "testuser", TimeSec: int32(now.Unix())},
	}

	data := buildTestUtmpxData(testEntries)
	tmpDir := t.TempDir()
	utmpxPath := filepath.Join(tmpDir, "utmpx")
	if err := os.WriteFile(utmpxPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPath := logonSessionsUtmpxPath
	logonSessionsUtmpxPath = utmpxPath
	defer func() { logonSessionsUtmpxPath = origPath }()

	cmd := &LogonSessionsCommand{}

	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if result.Status != "success" {
		t.Fatalf("list via Execute failed: %s: %s", result.Status, result.Output)
	}

	var entries []sessionEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 1 || entries[0].UserName != "testuser" {
		t.Errorf("unexpected output: %s", result.Output)
	}

	result = cmd.Execute(structs.Task{Params: `{"action":"users"}`})
	if result.Status != "success" {
		t.Fatalf("users via Execute failed: %s: %s", result.Status, result.Output)
	}
}
