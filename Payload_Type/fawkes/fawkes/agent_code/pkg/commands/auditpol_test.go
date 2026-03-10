//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestAuditSettingString_AllValues(t *testing.T) {
	tests := []struct {
		setting uint32
		want    string
	}{
		{auditPolicyNone, "No Auditing"},
		{auditPolicySuccess, "Success"},
		{auditPolicyFailure, "Failure"},
		{auditPolicySuccessFailure, "Success and Failure"},
	}

	for _, tt := range tests {
		got := auditSettingString(tt.setting)
		if got != tt.want {
			t.Errorf("auditSettingString(0x%X) = %q, want %q", tt.setting, got, tt.want)
		}
	}
}

func TestAuditSettingString_MasksHighBits(t *testing.T) {
	// High bits should be masked off — only bottom 2 bits matter
	got := auditSettingString(0x00000103) // high bits set + Success+Failure
	if got != "Success and Failure" {
		t.Errorf("auditSettingString(0x103) = %q, want %q", got, "Success and Failure")
	}

	got = auditSettingString(0xFFFFFF00) // all high bits, bottom 2 = 0
	if got != "No Auditing" {
		t.Errorf("auditSettingString(0xFFFFFF00) = %q, want %q", got, "No Auditing")
	}
}

func TestMatchSubcategories_All(t *testing.T) {
	matches := matchSubcategories("all")
	if len(matches) != len(auditSubcategories) {
		t.Errorf("matchSubcategories(\"all\") returned %d, want %d", len(matches), len(auditSubcategories))
	}
}

func TestMatchSubcategories_AllCaseInsensitive(t *testing.T) {
	matches := matchSubcategories("ALL")
	if len(matches) != len(auditSubcategories) {
		t.Errorf("matchSubcategories(\"ALL\") returned %d, want %d", len(matches), len(auditSubcategories))
	}
}

func TestMatchSubcategories_ExactCategory(t *testing.T) {
	matches := matchSubcategories("System")
	if len(matches) == 0 {
		t.Fatal("matchSubcategories(\"System\") returned 0 matches")
	}
	for _, m := range matches {
		if m.Category != "System" {
			t.Errorf("got category %q in System match", m.Category)
		}
	}
}

func TestMatchSubcategories_ExactSubcategory(t *testing.T) {
	matches := matchSubcategories("Process Creation")
	if len(matches) != 1 {
		t.Fatalf("matchSubcategories(\"Process Creation\") returned %d, want 1", len(matches))
	}
	if matches[0].Name != "Process Creation" {
		t.Errorf("got subcategory %q, want %q", matches[0].Name, "Process Creation")
	}
}

func TestMatchSubcategories_PartialMatch(t *testing.T) {
	// "Logon" should match both the "Logon/Logoff" category and the "Logon" subcategory
	matches := matchSubcategories("Logon")
	if len(matches) < 2 {
		t.Errorf("matchSubcategories(\"Logon\") returned %d, want >= 2", len(matches))
	}
}

func TestMatchSubcategories_CaseInsensitive(t *testing.T) {
	matches := matchSubcategories("process creation")
	if len(matches) != 1 {
		t.Fatalf("matchSubcategories(\"process creation\") returned %d, want 1", len(matches))
	}
	if matches[0].Name != "Process Creation" {
		t.Errorf("got %q, want %q", matches[0].Name, "Process Creation")
	}
}

func TestMatchSubcategories_NoMatch(t *testing.T) {
	matches := matchSubcategories("nonexistent-category")
	if len(matches) != 0 {
		t.Errorf("matchSubcategories(\"nonexistent\") returned %d, want 0", len(matches))
	}
}

func TestMatchSubcategories_Kerberos(t *testing.T) {
	matches := matchSubcategories("Kerberos")
	if len(matches) != 2 {
		t.Errorf("matchSubcategories(\"Kerberos\") returned %d, want 2 (Authentication Service + Service Ticket)", len(matches))
	}
}
