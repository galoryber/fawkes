package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestGpoName(t *testing.T) {
	cmd := &GpoCommand{}
	if cmd.Name() != "gpo" {
		t.Errorf("expected 'gpo', got '%s'", cmd.Name())
	}
}

func TestGpoDescription(t *testing.T) {
	cmd := &GpoCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestGpoExecuteEmptyParams(t *testing.T) {
	cmd := &GpoCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
}

func TestGpoExecuteInvalidJSON(t *testing.T) {
	cmd := &GpoCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestGpoExecuteMissingServer(t *testing.T) {
	cmd := &GpoCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if result.Status != "error" {
		t.Error("expected error for missing server")
	}
	if !strings.Contains(result.Output, "server parameter required") {
		t.Errorf("unexpected error: %s", result.Output)
	}
}

func TestGpoExecuteUnknownAction(t *testing.T) {
	cmd := &GpoCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"badaction","server":"127.0.0.1","port":1}`})
	if result.Status != "error" {
		t.Error("expected error")
	}
}

func TestGpoDefaultAction(t *testing.T) {
	cmd := &GpoCommand{}
	result := cmd.Execute(structs.Task{Params: `{"server":"127.0.0.1","port":1}`})
	if result.Status != "error" {
		t.Error("expected connection error")
	}
	if !strings.Contains(result.Output, "Error connecting") {
		t.Errorf("expected connection error, got: %s", result.Output)
	}
}

func TestGpoFlagsToString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "Enabled"},
		{"0", "Enabled"},
		{"1", "User Configuration Disabled"},
		{"2", "Computer Configuration Disabled"},
		{"3", "All Settings Disabled"},
		{"99", "Unknown (99)"},
		{"abc", "abc"},
	}
	for _, tc := range tests {
		result := gpoFlagsToString(tc.input)
		if result != tc.expected {
			t.Errorf("gpoFlagsToString(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestGpoFormatTime(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"20250115120000.0Z", "2025-01-15 12:00:00 UTC"},
		{"20260224083045.0Z", "2026-02-24 08:30:45 UTC"},
		{"short", "short"},
		{"", ""},
		{"not-a-time-value", "not-a-time-value"},
	}
	for _, tc := range tests {
		result := gpoFormatTime(tc.input)
		if result != tc.expected {
			t.Errorf("gpoFormatTime(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestGpoCategorizeFinding(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Scripts (Startup/Shutdown/Logon/Logoff)", "Scripts & Execution"},
		{"Security Settings", "Security Configuration"},
		{"Audit Policy Configuration", "Security Configuration"},
		{"Scheduled Tasks (Preferences)", "Scheduled Tasks"},
		{"Local Users and Groups (Preferences)", "User & Group Management"},
		{"EFS Recovery", "Credential & Certificate"},
		{"IP Security", "Security Configuration"},
		{"Windows Firewall", "Network Configuration"},
		{"Wireless Group Policy", "Network Configuration"},
		{"Network Options (VPN/Dial-up)", "Network Configuration"},
		{"Software Installation", "Software Deployment"},
		{"Registry (Preferences)", "Other"},
		{"Drive Mapping (Preferences)", "Other"},
		{"Environment Variables (Preferences)", "Other"},
		{"Data Sources (Preferences)", "Other"},
		{"Network Shares (Preferences)", "Network Configuration"},
		{"Something Unknown", "Other"},
	}
	for _, tc := range tests {
		result := gpoCategorizeFinding(tc.input)
		if result != tc.expected {
			t.Errorf("gpoCategorizeFinding(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestGpoLinkRegex(t *testing.T) {
	tests := []struct {
		input       string
		expectMatch bool
		expectGUID  string
		expectFlags string
	}{
		{
			"[LDAP://cn={6AC1786C-016F-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=test,DC=local;0]",
			true, "6AC1786C-016F-11D2-945F-00C04FB984F9", "0",
		},
		{
			"[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=domain,DC=com;2]",
			true, "31B2F340-016D-11D2-945F-00C04FB984F9", "2",
		},
		{
			// Multiple links in one gPLink value
			"[LDAP://cn={AAA11111-0000-0000-0000-000000000000},cn=policies,cn=system,DC=x;0][LDAP://cn={BBB22222-0000-0000-0000-000000000000},cn=policies,cn=system,DC=x;2]",
			true, "AAA11111-0000-0000-0000-000000000000", "0",
		},
		{
			"no link here",
			false, "", "",
		},
	}
	for _, tc := range tests {
		matches := gpoLinkRegex.FindAllStringSubmatch(tc.input, -1)
		if tc.expectMatch {
			if len(matches) == 0 {
				t.Errorf("expected match for %q, got none", tc.input)
				continue
			}
			if !strings.EqualFold(matches[0][1], tc.expectGUID) {
				t.Errorf("GUID mismatch for %q: got %s, want %s", tc.input, matches[0][1], tc.expectGUID)
			}
			if matches[0][2] != tc.expectFlags {
				t.Errorf("flags mismatch for %q: got %s, want %s", tc.input, matches[0][2], tc.expectFlags)
			}
		} else {
			if len(matches) > 0 {
				t.Errorf("expected no match for %q, got %v", tc.input, matches)
			}
		}
	}

	// Test multiple links extraction
	multiLink := "[LDAP://cn={AAA11111-0000-0000-0000-000000000000},cn=policies,cn=system,DC=x;0][LDAP://cn={BBB22222-0000-0000-0000-000000000000},cn=policies,cn=system,DC=x;2]"
	matches := gpoLinkRegex.FindAllStringSubmatch(multiLink, -1)
	if len(matches) != 2 {
		t.Errorf("expected 2 matches for multi-link, got %d", len(matches))
	}
	if len(matches) >= 2 {
		if !strings.EqualFold(matches[1][1], "BBB22222-0000-0000-0000-000000000000") {
			t.Errorf("second GUID: got %s, want BBB22222-0000-0000-0000-000000000000", matches[1][1])
		}
		if matches[1][2] != "2" {
			t.Errorf("second flags: got %s, want 2", matches[1][2])
		}
	}
}

func TestGpoLinkRegexEnforced(t *testing.T) {
	// flags: 0=none, 1=disabled, 2=enforced, 3=enforced+disabled
	link := "[LDAP://cn={12345678-1234-1234-1234-123456789012},cn=policies,cn=system,DC=test,DC=local;2]"
	matches := gpoLinkRegex.FindAllStringSubmatch(link, -1)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	flags := matches[0][2]
	if flags != "2" {
		t.Errorf("expected flags=2 (enforced), got %s", flags)
	}
}

func TestInterestingCSEsNotEmpty(t *testing.T) {
	if len(interestingCSEs) == 0 {
		t.Error("interestingCSEs should not be empty")
	}
	// Verify all CSE GUIDs have proper format
	for guid, name := range interestingCSEs {
		if !strings.HasPrefix(guid, "{") || !strings.HasSuffix(guid, "}") {
			t.Errorf("CSE GUID %q should be wrapped in braces", guid)
		}
		if name == "" {
			t.Errorf("CSE name for %s should not be empty", guid)
		}
	}
}
