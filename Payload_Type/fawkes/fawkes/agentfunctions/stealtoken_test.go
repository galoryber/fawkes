package agentfunctions

import (
	"testing"
)

// --- selectBestToken Tests ---

func TestSelectBestToken_SystemFirst(t *testing.T) {
	tokens := []autoEscalateToken{
		{PID: 100, User: "MYPC\\setup", Integrity: "Medium"},
		{PID: 200, User: "NT AUTHORITY\\SYSTEM", Integrity: "System"},
		{PID: 300, User: "MYPC\\admin", Integrity: "High"},
	}
	result := selectBestToken(tokens, "MYPC\\other")
	if result == nil {
		t.Fatal("selectBestToken returned nil")
	}
	if result.PID != 200 {
		t.Errorf("expected SYSTEM token (PID 200), got PID %d user %q", result.PID, result.User)
	}
}

func TestSelectBestToken_HighIntegrityOverMedium(t *testing.T) {
	tokens := []autoEscalateToken{
		{PID: 100, User: "MYPC\\setup", Integrity: "Medium"},
		{PID: 300, User: "MYPC\\admin", Integrity: "High"},
		{PID: 400, User: "MYPC\\user2", Integrity: "Medium"},
	}
	result := selectBestToken(tokens, "MYPC\\other")
	if result == nil {
		t.Fatal("selectBestToken returned nil")
	}
	if result.PID != 300 {
		t.Errorf("expected High integrity token (PID 300), got PID %d", result.PID)
	}
}

func TestSelectBestToken_SkipsCurrentUser(t *testing.T) {
	tokens := []autoEscalateToken{
		{PID: 100, User: "NT AUTHORITY\\SYSTEM", Integrity: "System"},
		{PID: 200, User: "MYPC\\currentuser", Integrity: "Medium"},
	}
	// Current user is SYSTEM — should skip SYSTEM token and return the other
	result := selectBestToken(tokens, "NT AUTHORITY\\SYSTEM")
	if result == nil {
		t.Fatal("selectBestToken returned nil")
	}
	if result.PID != 200 {
		t.Errorf("expected non-current-user token (PID 200), got PID %d", result.PID)
	}
}

func TestSelectBestToken_CaseInsensitiveCurrentUser(t *testing.T) {
	tokens := []autoEscalateToken{
		{PID: 100, User: "MYPC\\Setup", Integrity: "Medium"},
		{PID: 200, User: "MYPC\\admin", Integrity: "High"},
	}
	result := selectBestToken(tokens, "mypc\\setup")
	if result == nil {
		t.Fatal("selectBestToken returned nil")
	}
	if result.PID != 200 {
		t.Errorf("expected to skip current user (case-insensitive), got PID %d", result.PID)
	}
}

func TestSelectBestToken_AllCurrentUser(t *testing.T) {
	tokens := []autoEscalateToken{
		{PID: 100, User: "MYPC\\me", Integrity: "Medium"},
		{PID: 200, User: "MYPC\\me", Integrity: "High"},
	}
	result := selectBestToken(tokens, "MYPC\\me")
	if result != nil {
		t.Errorf("expected nil when all tokens are current user, got PID %d", result.PID)
	}
}

func TestSelectBestToken_EmptyList(t *testing.T) {
	result := selectBestToken(nil, "MYPC\\me")
	if result != nil {
		t.Error("expected nil for empty token list")
	}
}

func TestSelectBestToken_SystemDetection(t *testing.T) {
	// Various SYSTEM user formats
	tests := []struct {
		user string
		want bool
	}{
		{"NT AUTHORITY\\SYSTEM", true},
		{"SYSTEM", true},
		{"nt authority\\system", true},
		{"LOCAL SYSTEM", true},
		{"MYPC\\admin", false},
	}

	for _, tt := range tests {
		tokens := []autoEscalateToken{
			{PID: 1, User: tt.user, Integrity: "System"},
		}
		result := selectBestToken(tokens, "other")
		if tt.want && result == nil {
			t.Errorf("user %q should be detected as SYSTEM", tt.user)
		}
	}
}

func TestSelectBestToken_FallbackToOther(t *testing.T) {
	// No SYSTEM, no High — should return Medium/other tokens
	tokens := []autoEscalateToken{
		{PID: 100, User: "MYPC\\user1", Integrity: "Medium"},
		{PID: 200, User: "MYPC\\user2", Integrity: "Low"},
	}
	result := selectBestToken(tokens, "MYPC\\currentuser")
	if result == nil {
		t.Fatal("selectBestToken returned nil")
	}
	// Should return the first available non-current-user token
	if result.PID != 100 && result.PID != 200 {
		t.Errorf("expected one of the other tokens, got PID %d", result.PID)
	}
}

func TestSelectBestToken_SystemIntegrityIsHighTier(t *testing.T) {
	// Token with Integrity="System" but user is not "SYSTEM" string
	tokens := []autoEscalateToken{
		{PID: 100, User: "MYPC\\svcaccount", Integrity: "System"},
		{PID: 200, User: "MYPC\\user", Integrity: "Medium"},
	}
	result := selectBestToken(tokens, "other")
	if result == nil {
		t.Fatal("selectBestToken returned nil")
	}
	// Integrity "System" should be in high-tier
	if result.PID != 100 {
		t.Errorf("expected System integrity token (PID 100), got PID %d", result.PID)
	}
}
