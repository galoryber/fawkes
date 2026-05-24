//go:build windows
// +build windows

package commands

import (
	"strings"
	"testing"
)

func TestStoredCredentials_Fields(t *testing.T) {
	creds := &StoredCredentials{
		Domain:   "CORP",
		Username: "admin",
		Password: "P@ssw0rd",
	}
	if creds.Domain != "CORP" {
		t.Errorf("Domain = %q, want %q", creds.Domain, "CORP")
	}
	if creds.Username != "admin" {
		t.Errorf("Username = %q, want %q", creds.Username, "admin")
	}
	if creds.Password != "P@ssw0rd" {
		t.Errorf("Password = %q, want %q", creds.Password, "P@ssw0rd")
	}
}

func TestZeroStoredCredentials_Nil(t *testing.T) {
	// Should not panic on nil
	zeroStoredCredentials(nil)
}

func TestSavedToken_Fields(t *testing.T) {
	saved := &SavedToken{
		Identity: `CORP\admin`,
		Source:   "make-token",
		Creds: &StoredCredentials{
			Domain:   "CORP",
			Username: "admin",
			Password: "pass",
		},
	}
	if saved.Identity != `CORP\admin` {
		t.Errorf("Identity = %q, want %q", saved.Identity, `CORP\admin`)
	}
	if saved.Source != "make-token" {
		t.Errorf("Source = %q, want %q", saved.Source, "make-token")
	}
	if saved.Creds == nil {
		t.Fatal("Creds should not be nil")
		return // unreachable, helps staticcheck
	}
}

func TestSetIdentityCredentials_And_Get(t *testing.T) {
	// Clear any prior state
	tokenMutex.Lock()
	gIdentityCreds = nil
	tokenMutex.Unlock()

	SetIdentityCredentials("TESTDOMAIN", "testuser", "testpass")
	got := GetIdentityCredentials()
	if got == nil {
		t.Fatal("GetIdentityCredentials returned nil")
	}
	if got.Domain != "TESTDOMAIN" {
		t.Errorf("Domain = %q, want %q", got.Domain, "TESTDOMAIN")
	}
	if got.Username != "testuser" {
		t.Errorf("Username = %q, want %q", got.Username, "testuser")
	}
	if got.Password != "testpass" {
		t.Errorf("Password = %q, want %q", got.Password, "testpass")
	}

	// Verify it returns a copy (modifying returned struct doesn't affect stored)
	got.Password = "modified"
	got2 := GetIdentityCredentials()
	if got2.Password != "testpass" {
		t.Errorf("GetIdentityCredentials should return a copy, but stored password changed to %q", got2.Password)
	}

	// Cleanup
	tokenMutex.Lock()
	gIdentityCreds = nil
	tokenMutex.Unlock()
}

func TestGetIdentityCredentials_ReturnsNilWhenEmpty(t *testing.T) {
	tokenMutex.Lock()
	gIdentityCreds = nil
	tokenMutex.Unlock()

	got := GetIdentityCredentials()
	if got != nil {
		t.Errorf("Expected nil when no credentials stored, got %+v", got)
	}
}

func TestListTokenStore_EmptyStore(t *testing.T) {
	// Ensure store is empty
	tokenMutex.Lock()
	origStore := gTokenStore
	gTokenStore = make(map[string]*SavedToken)
	tokenMutex.Unlock()

	defer func() {
		tokenMutex.Lock()
		gTokenStore = origStore
		tokenMutex.Unlock()
	}()

	result := ListTokenStore()
	if len(result) != 0 {
		t.Errorf("Expected empty store, got %d entries", len(result))
	}
}

func TestRemoveTokenFromStore_NonExistent(t *testing.T) {
	tokenMutex.Lock()
	origStore := gTokenStore
	gTokenStore = make(map[string]*SavedToken)
	tokenMutex.Unlock()

	defer func() {
		tokenMutex.Lock()
		gTokenStore = origStore
		tokenMutex.Unlock()
	}()

	err := RemoveTokenFromStore("nonexistent")
	if err == nil {
		t.Error("Removing nonexistent token should return error")
	}
}

func TestSaveTokenToStore_NoActiveToken(t *testing.T) {
	tokenMutex.Lock()
	origToken := gIdentityToken
	gIdentityToken = 0
	tokenMutex.Unlock()

	defer func() {
		tokenMutex.Lock()
		gIdentityToken = origToken
		tokenMutex.Unlock()
	}()

	err := SaveTokenToStore("test", "test-source")
	if err == nil {
		t.Error("SaveTokenToStore with no active token should return error")
	}
}

func TestUseTokenFromStore_NonExistent(t *testing.T) {
	tokenMutex.Lock()
	origStore := gTokenStore
	gTokenStore = make(map[string]*SavedToken)
	tokenMutex.Unlock()

	defer func() {
		tokenMutex.Lock()
		gTokenStore = origStore
		tokenMutex.Unlock()
	}()

	_, err := UseTokenFromStore("nonexistent")
	if err == nil {
		t.Error("UseTokenFromStore with nonexistent name should return error")
	}
}

// --- Identity History Tests ---

func TestRecordIdentityTransition_Basic(t *testing.T) {
	// Clear history
	tokenMutex.Lock()
	origHistory := gIdentityHistory
	gIdentityHistory = nil
	tokenMutex.Unlock()
	defer func() {
		tokenMutex.Lock()
		gIdentityHistory = origHistory
		tokenMutex.Unlock()
	}()

	RecordIdentityTransition("stealtoken", "DESKTOP\\setup", "NT AUTHORITY\\SYSTEM", "PID 1234")

	history := GetIdentityHistory()
	if len(history) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(history))
	}
	if history[0].Operation != "stealtoken" {
		t.Errorf("Operation = %q, want %q", history[0].Operation, "stealtoken")
	}
	if history[0].FromUser != "DESKTOP\\setup" {
		t.Errorf("FromUser = %q, want %q", history[0].FromUser, "DESKTOP\\setup")
	}
	if history[0].ToUser != "NT AUTHORITY\\SYSTEM" {
		t.Errorf("ToUser = %q, want %q", history[0].ToUser, "NT AUTHORITY\\SYSTEM")
	}
	if history[0].Level != "SYSTEM" {
		t.Errorf("Level = %q, want %q", history[0].Level, "SYSTEM")
	}
	if history[0].Detail != "PID 1234" {
		t.Errorf("Detail = %q, want %q", history[0].Detail, "PID 1234")
	}
	if history[0].Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestRecordIdentityTransition_MultipleEvents(t *testing.T) {
	tokenMutex.Lock()
	origHistory := gIdentityHistory
	gIdentityHistory = nil
	tokenMutex.Unlock()
	defer func() {
		tokenMutex.Lock()
		gIdentityHistory = origHistory
		tokenMutex.Unlock()
	}()

	RecordIdentityTransition("maketoken", "DESKTOP\\setup", "CORP\\admin", "CORP\\admin")
	RecordIdentityTransition("rev2self", "CORP\\admin", "DESKTOP\\setup", "")
	RecordIdentityTransition("getsystem", "DESKTOP\\setup", "NT AUTHORITY\\SYSTEM", "steal from winlogon.exe")

	history := GetIdentityHistory()
	if len(history) != 3 {
		t.Fatalf("Expected 3 events, got %d", len(history))
	}
	if history[0].Operation != "maketoken" {
		t.Errorf("Event 0: Operation = %q, want %q", history[0].Operation, "maketoken")
	}
	if history[1].Operation != "rev2self" {
		t.Errorf("Event 1: Operation = %q, want %q", history[1].Operation, "rev2self")
	}
	if history[2].Operation != "getsystem" {
		t.Errorf("Event 2: Operation = %q, want %q", history[2].Operation, "getsystem")
	}
}

func TestRecordIdentityTransition_Cap(t *testing.T) {
	tokenMutex.Lock()
	origHistory := gIdentityHistory
	gIdentityHistory = nil
	tokenMutex.Unlock()
	defer func() {
		tokenMutex.Lock()
		gIdentityHistory = origHistory
		tokenMutex.Unlock()
	}()

	// Fill beyond max
	for i := 0; i < maxIdentityHistory+10; i++ {
		RecordIdentityTransition("stealtoken", "old", "new", "")
	}

	history := GetIdentityHistory()
	if len(history) != maxIdentityHistory {
		t.Errorf("Expected %d events (capped), got %d", maxIdentityHistory, len(history))
	}
}

func TestGetIdentityHistoryJSON_Empty(t *testing.T) {
	tokenMutex.Lock()
	origHistory := gIdentityHistory
	gIdentityHistory = nil
	tokenMutex.Unlock()
	defer func() {
		tokenMutex.Lock()
		gIdentityHistory = origHistory
		tokenMutex.Unlock()
	}()

	json := GetIdentityHistoryJSON()
	if json != "[]" {
		t.Errorf("Expected empty JSON array, got %q", json)
	}
}

func TestGetIdentityHistoryJSON_WithEvents(t *testing.T) {
	tokenMutex.Lock()
	origHistory := gIdentityHistory
	gIdentityHistory = nil
	tokenMutex.Unlock()
	defer func() {
		tokenMutex.Lock()
		gIdentityHistory = origHistory
		tokenMutex.Unlock()
	}()

	RecordIdentityTransition("maketoken", "user1", "admin1", "test")

	json := GetIdentityHistoryJSON()
	if json == "[]" {
		t.Error("Expected non-empty JSON")
	}
	if !strings.Contains(json, "maketoken") {
		t.Errorf("JSON should contain operation, got %q", json)
	}
	if !strings.Contains(json, "admin1") {
		t.Errorf("JSON should contain to_user, got %q", json)
	}
}

func TestGetIdentityHistory_ReturnsCopy(t *testing.T) {
	tokenMutex.Lock()
	origHistory := gIdentityHistory
	gIdentityHistory = nil
	tokenMutex.Unlock()
	defer func() {
		tokenMutex.Lock()
		gIdentityHistory = origHistory
		tokenMutex.Unlock()
	}()

	RecordIdentityTransition("stealtoken", "a", "b", "")
	history := GetIdentityHistory()
	history[0].Operation = "modified"

	original := GetIdentityHistory()
	if original[0].Operation == "modified" {
		t.Error("GetIdentityHistory should return a copy, not a reference")
	}
}

func TestClassifyIdentityLevelLocal(t *testing.T) {
	tests := []struct {
		user     string
		expected string
	}{
		{"NT AUTHORITY\\SYSTEM", "SYSTEM"},
		{"CORP\\Administrator", "admin"},
		{"DESKTOP\\regularuser", "user"},
		{"nt authority\\system", "SYSTEM"},
		{"Domain Admins", "admin"},
		{"Enterprise Admin Group", "admin"},
		{"", "user"},
	}
	for _, tt := range tests {
		level := classifyIdentityLevelLocal(tt.user)
		if level != tt.expected {
			t.Errorf("classifyIdentityLevelLocal(%q) = %q, want %q", tt.user, level, tt.expected)
		}
	}
}

func TestLogonConstants(t *testing.T) {
	// Verify critical Windows API constants
	if LOGON32_LOGON_NEW_CREDENTIALS != 9 {
		t.Errorf("LOGON32_LOGON_NEW_CREDENTIALS = %d, want 9", LOGON32_LOGON_NEW_CREDENTIALS)
	}
	if LOGON32_LOGON_INTERACTIVE != 2 {
		t.Errorf("LOGON32_LOGON_INTERACTIVE = %d, want 2", LOGON32_LOGON_INTERACTIVE)
	}
	if STEAL_TOKEN_ACCESS != (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE) {
		t.Errorf("STEAL_TOKEN_ACCESS = 0x%X, want 0x%X", STEAL_TOKEN_ACCESS, TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_IMPERSONATE)
	}
}
