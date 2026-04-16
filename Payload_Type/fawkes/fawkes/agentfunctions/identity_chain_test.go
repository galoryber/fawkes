package agentfunctions

import (
	"strings"
	"testing"
)

func TestFormatIdentityDescription_Stealtoken(t *testing.T) {
	desc := formatIdentityDescription("stealtoken", "CORP\\admin")
	if !strings.Contains(desc, "CORP\\admin") {
		t.Errorf("Expected user in description, got %q", desc)
	}
	if !strings.Contains(desc, "stealtoken") {
		t.Errorf("Expected stealtoken in description, got %q", desc)
	}
}

func TestFormatIdentityDescription_Maketoken(t *testing.T) {
	desc := formatIdentityDescription("maketoken", "DOMAIN\\svc_account")
	if !strings.Contains(desc, "DOMAIN\\svc_account") {
		t.Errorf("Expected user in description, got %q", desc)
	}
	if !strings.Contains(desc, "maketoken") {
		t.Errorf("Expected maketoken in description, got %q", desc)
	}
}

func TestFormatIdentityDescription_Rev2self(t *testing.T) {
	desc := formatIdentityDescription("rev2self", "DESKTOP-ABC\\setup")
	if !strings.Contains(desc, "Reverted") {
		t.Errorf("Expected 'Reverted' in description, got %q", desc)
	}
}

func TestClassifyIdentityLevel_System(t *testing.T) {
	tests := []struct {
		user     string
		expected string
	}{
		{"NT AUTHORITY\\SYSTEM", "SYSTEM"},
		{"NT AUTHORITY\\LOCAL SERVICE", "SYSTEM"},
		{"CORP\\Administrator", "admin"},
		{"DOMAIN\\Domain Admins", "admin"},
		{"DESKTOP\\regularuser", "user"},
		{"john.doe", "user"},
	}
	for _, tt := range tests {
		level := classifyIdentityLevel(tt.user)
		if level != tt.expected {
			t.Errorf("classifyIdentityLevel(%q) = %q, want %q", tt.user, level, tt.expected)
		}
	}
}

func TestIdentityContextForOPSEC_Empty(t *testing.T) {
	ctx := identityContextForOPSEC("")
	if ctx != "" {
		t.Errorf("Expected empty context for empty desc, got %q", ctx)
	}
}

func TestIdentityContextForOPSEC_Impersonating(t *testing.T) {
	desc := "Impersonating: CORP\\admin (via maketoken)"
	ctx := identityContextForOPSEC(desc)
	if ctx != desc {
		t.Errorf("Expected desc returned for impersonating, got %q", ctx)
	}
}

func TestIdentityContextForOPSEC_NotImpersonating(t *testing.T) {
	ctx := identityContextForOPSEC("Some other description")
	if ctx != "" {
		t.Errorf("Expected empty for non-impersonation desc, got %q", ctx)
	}
}

func TestFormatIdentityDescription_Getsystem(t *testing.T) {
	desc := formatIdentityDescription("getsystem", "NT AUTHORITY\\SYSTEM")
	if !strings.Contains(desc, "Elevated") {
		t.Errorf("Expected 'Elevated' in getsystem description, got %q", desc)
	}
	if !strings.Contains(desc, "SYSTEM") {
		t.Errorf("Expected 'SYSTEM' in getsystem description, got %q", desc)
	}
}

func TestFormatIdentityDescription_Unknown(t *testing.T) {
	desc := formatIdentityDescription("custom-op", "some-user")
	if !strings.Contains(desc, "some-user") {
		t.Errorf("Expected user in default description, got %q", desc)
	}
	if !strings.Contains(desc, "custom-op") {
		t.Errorf("Expected operation in default description, got %q", desc)
	}
}

func TestIdentityContextForOPSEC_Reverted(t *testing.T) {
	// "Reverted to:" should NOT trigger context (user is back to original identity)
	ctx := identityContextForOPSEC("Reverted to: DESKTOP\\setup")
	if ctx != "" {
		t.Errorf("Expected empty for reverted desc, got %q", ctx)
	}
}

func TestClassifyIdentityLevel_EnterpriseAdmin(t *testing.T) {
	level := classifyIdentityLevel("CORP\\Enterprise Admins")
	if level != "admin" {
		t.Errorf("Expected admin for Enterprise Admin, got %q", level)
	}
}

func TestClassifyIdentityLevel_EmptyUser(t *testing.T) {
	level := classifyIdentityLevel("")
	if level != "user" {
		t.Errorf("Expected user for empty string, got %q", level)
	}
}
