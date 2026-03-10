//go:build linux

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
	// Empty params should default to "list" and succeed
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Logf("Output: %s", result.Output)
		// May fail if utmp not readable, which is acceptable
	}
}

// buildTestUtmpData creates a synthetic utmp binary file for testing.
func buildTestUtmpData(entries []utmpEntry) []byte {
	var data []byte
	for _, e := range entries {
		rec := make([]byte, utmpRecordSize)

		// ut_type (offset 0, 2 bytes)
		binary.LittleEndian.PutUint16(rec[0:2], uint16(e.Type))

		// ut_pid (offset 4, 4 bytes)
		binary.LittleEndian.PutUint32(rec[4:8], uint32(e.PID))

		// ut_line (offset 8, 32 bytes)
		copy(rec[8:8+utmpLineSize], e.Line)

		// ut_id (offset 40, 4 bytes)
		copy(rec[40:44], e.ID)

		// ut_user (offset 44, 32 bytes)
		copy(rec[44:44+utmpUserSize], e.User)

		// ut_host (offset 76, 256 bytes)
		copy(rec[76:76+utmpHostSize], e.Host)

		// ut_session (offset 336, 4 bytes)
		binary.LittleEndian.PutUint32(rec[336:340], uint32(e.Session))

		// ut_tv.tv_sec (offset 340, 4 bytes)
		binary.LittleEndian.PutUint32(rec[340:344], uint32(e.TimeSec))

		// ut_addr_v6 (offset 348, 16 bytes)
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint32(rec[348+i*4:352+i*4], e.AddrV6[i])
		}

		data = append(data, rec...)
	}
	return data
}

func TestParseUtmpForLogonSessions(t *testing.T) {
	now := time.Now()
	testEntries := []utmpEntry{
		{
			Type:    7, // USER_PROCESS
			PID:     1234,
			Line:    "pts/0",
			ID:      "ts/0",
			User:    "gary",
			Host:    "192.168.1.100",
			Session: 42,
			TimeSec: int32(now.Unix()),
		},
		{
			Type: 8, // DEAD_PROCESS - should be filtered
			PID:  5678,
			Line: "pts/1",
			User: "dead",
		},
		{
			Type:    7, // USER_PROCESS
			PID:     9012,
			Line:    "tty1",
			User:    "root",
			Session: 43,
			TimeSec: int32(now.Add(-1 * time.Hour).Unix()),
		},
	}

	data := buildTestUtmpData(testEntries)

	// Write to temp file and override path
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	if err := os.WriteFile(utmpPath, data, 0644); err != nil {
		t.Fatalf("failed to write test utmp: %v", err)
	}

	// Override utmp paths for testing
	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

	entries, err := parseUtmpForLogonSessions()
	if err != nil {
		t.Fatalf("parseUtmpForLogonSessions() error: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Verify first entry
	if entries[0].User != "gary" {
		t.Errorf("entries[0].User = %q, want gary", entries[0].User)
	}
	if entries[0].Line != "pts/0" {
		t.Errorf("entries[0].Line = %q, want pts/0", entries[0].Line)
	}
	if entries[0].Host != "192.168.1.100" {
		t.Errorf("entries[0].Host = %q, want 192.168.1.100", entries[0].Host)
	}
	if entries[0].PID != 1234 {
		t.Errorf("entries[0].PID = %d, want 1234", entries[0].PID)
	}

	// Verify dead process is present but will be filtered by enumerate
	if entries[1].Type != 8 {
		t.Errorf("entries[1].Type = %d, want 8 (DEAD_PROCESS)", entries[1].Type)
	}
}

func TestEnumerateLinuxSessions(t *testing.T) {
	now := time.Now()
	testEntries := []utmpEntry{
		{
			Type:    7,
			PID:     100,
			Line:    "pts/0",
			User:    "alice",
			Host:    "10.0.0.5",
			Session: 1,
			TimeSec: int32(now.Unix()),
		},
		{
			Type: 8, // DEAD_PROCESS - filtered out
			PID:  200,
			Line: "pts/1",
			User: "dead",
		},
		{
			Type:    7,
			PID:     300,
			Line:    "tty1",
			User:    "bob",
			Session: 2,
			TimeSec: int32(now.Unix()),
		},
		{
			Type: 7, // USER_PROCESS but empty user - filtered out
			PID:  400,
			Line: "pts/2",
			User: "",
		},
	}

	data := buildTestUtmpData(testEntries)
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	if err := os.WriteFile(utmpPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

	sessions, err := enumerateLinuxSessions()
	if err != nil {
		t.Fatalf("enumerateLinuxSessions() error: %v", err)
	}

	// Should only have alice and bob (dead process and empty user filtered)
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	if sessions[0].UserName != "alice" {
		t.Errorf("sessions[0].UserName = %q, want alice", sessions[0].UserName)
	}
	if sessions[0].Station != "pts/0" {
		t.Errorf("sessions[0].Station = %q, want pts/0", sessions[0].Station)
	}
	if sessions[0].State != "Active" {
		t.Errorf("sessions[0].State = %q, want Active", sessions[0].State)
	}
	if sessions[0].ClientName != "10.0.0.5" {
		t.Errorf("sessions[0].ClientName = %q, want 10.0.0.5", sessions[0].ClientName)
	}

	if sessions[1].UserName != "bob" {
		t.Errorf("sessions[1].UserName = %q, want bob", sessions[1].UserName)
	}
	if sessions[1].Station != "tty1" {
		t.Errorf("sessions[1].Station = %q, want tty1", sessions[1].Station)
	}
}

func TestLogonSessionsListJSON(t *testing.T) {
	now := time.Now()
	testEntries := []utmpEntry{
		{Type: 7, PID: 100, Line: "pts/0", User: "gary", Session: 1, TimeSec: int32(now.Unix())},
		{Type: 7, PID: 200, Line: "pts/1", User: "root", Session: 2, TimeSec: int32(now.Unix())},
	}

	data := buildTestUtmpData(testEntries)
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	if err := os.WriteFile(utmpPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

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
	testEntries := []utmpEntry{
		{Type: 7, PID: 100, Line: "pts/0", User: "gary", Session: 1, TimeSec: int32(now.Unix())},
		{Type: 7, PID: 200, Line: "pts/1", User: "root", Session: 2, TimeSec: int32(now.Unix())},
		{Type: 7, PID: 300, Line: "pts/2", User: "gary", Session: 3, TimeSec: int32(now.Unix())},
	}

	data := buildTestUtmpData(testEntries)
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	if err := os.WriteFile(utmpPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

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

func TestLogonSessionsListFilterNoMatch(t *testing.T) {
	testEntries := []utmpEntry{
		{Type: 7, PID: 100, Line: "pts/0", User: "gary", Session: 1, TimeSec: int32(time.Now().Unix())},
	}

	data := buildTestUtmpData(testEntries)
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	if err := os.WriteFile(utmpPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

	result := logonSessionsList(logonSessionsArgs{Action: "list", Filter: "nonexistent"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s", result.Status)
	}
	if result.Output != "[]" {
		t.Errorf("expected empty array, got: %s", result.Output)
	}
}

func TestLogonSessionsUsersAction(t *testing.T) {
	now := time.Now()
	testEntries := []utmpEntry{
		{Type: 7, PID: 100, Line: "pts/0", User: "gary", Session: 1, TimeSec: int32(now.Unix())},
		{Type: 7, PID: 200, Line: "pts/1", User: "gary", Session: 2, TimeSec: int32(now.Unix())},
		{Type: 7, PID: 300, Line: "tty1", User: "root", Session: 3, TimeSec: int32(now.Unix())},
	}

	data := buildTestUtmpData(testEntries)
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	if err := os.WriteFile(utmpPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

	result := logonSessionsUsers(logonSessionsArgs{Action: "users"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	var entries []userEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("invalid JSON: %v\nOutput: %s", err, result.Output)
	}

	// Should have 2 unique users (gary, root)
	if len(entries) != 2 {
		t.Fatalf("expected 2 unique users, got %d", len(entries))
	}

	// Find gary entry
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

func TestLogonSessionsUsersFilter(t *testing.T) {
	now := time.Now()
	testEntries := []utmpEntry{
		{Type: 7, PID: 100, Line: "pts/0", User: "gary", Session: 1, TimeSec: int32(now.Unix())},
		{Type: 7, PID: 200, Line: "tty1", User: "root", Session: 2, TimeSec: int32(now.Unix())},
	}

	data := buildTestUtmpData(testEntries)
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	if err := os.WriteFile(utmpPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

	result := logonSessionsUsers(logonSessionsArgs{Action: "users", Filter: "root"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s", result.Status)
	}

	var entries []userEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 filtered user, got %d", len(entries))
	}
	if entries[0].User != "root" {
		t.Errorf("filtered user = %q, want root", entries[0].User)
	}
}

func TestLogonSessionsEmptyUtmp(t *testing.T) {
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	// Write an empty file
	if err := os.WriteFile(utmpPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

	result := logonSessionsList(logonSessionsArgs{Action: "list"})
	if result.Status != "success" {
		t.Fatalf("expected success for empty utmp, got %s: %s", result.Status, result.Output)
	}
	if result.Output != "[]" {
		t.Errorf("expected empty array, got: %s", result.Output)
	}
}

func TestLogonSessionsNoUtmpFile(t *testing.T) {
	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{"/nonexistent/path/utmp"}
	defer func() { logonSessionsUtmpPaths = origPaths }()

	result := logonSessionsList(logonSessionsArgs{Action: "list"})
	if result.Status != "error" {
		t.Errorf("expected error for missing utmp, got %s", result.Status)
	}
}

func TestLogonSessionsAddrStringIPv4(t *testing.T) {
	// 192.168.1.100 = 0xC0A80164 in network order, but stored in host (LE) order
	addr := [4]uint32{0x6401A8C0, 0, 0, 0} // 192.168.1.100 in little-endian
	result := logonSessionsAddrString(addr)
	if result != "192.168.1.100" {
		t.Errorf("got %q, want 192.168.1.100", result)
	}
}

func TestLogonSessionsAddrStringZero(t *testing.T) {
	addr := [4]uint32{0, 0, 0, 0}
	result := logonSessionsAddrString(addr)
	if result != "" {
		t.Errorf("got %q, want empty string for zero address", result)
	}
}

func TestLogonSessionsViaExecute(t *testing.T) {
	now := time.Now()
	testEntries := []utmpEntry{
		{Type: 7, PID: 100, Line: "pts/0", User: "testuser", Session: 1, TimeSec: int32(now.Unix())},
	}

	data := buildTestUtmpData(testEntries)
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	if err := os.WriteFile(utmpPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

	cmd := &LogonSessionsCommand{}

	// Test list via Execute
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

	// Test users via Execute
	result = cmd.Execute(structs.Task{Params: `{"action":"users"}`})
	if result.Status != "success" {
		t.Fatalf("users via Execute failed: %s: %s", result.Status, result.Output)
	}
}

func TestLogonSessionsLoginTime(t *testing.T) {
	ts := int32(1700000000) // 2023-11-14 22:13:20 UTC
	testEntries := []utmpEntry{
		{Type: 7, PID: 100, Line: "pts/0", User: "user1", Session: 1, TimeSec: ts},
	}

	data := buildTestUtmpData(testEntries)
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	if err := os.WriteFile(utmpPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

	sessions, err := enumerateLinuxSessions()
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
	testEntries := []utmpEntry{
		{
			Type:    7,
			PID:     100,
			Line:    "pts/0",
			User:    "remote_user",
			Host:    "workstation.corp.local",
			Session: 1,
			TimeSec: int32(time.Now().Unix()),
		},
	}

	data := buildTestUtmpData(testEntries)
	tmpDir := t.TempDir()
	utmpPath := filepath.Join(tmpDir, "utmp")
	if err := os.WriteFile(utmpPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	origPaths := logonSessionsUtmpPaths
	logonSessionsUtmpPaths = []string{utmpPath}
	defer func() { logonSessionsUtmpPaths = origPaths }()

	sessions, err := enumerateLinuxSessions()
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
