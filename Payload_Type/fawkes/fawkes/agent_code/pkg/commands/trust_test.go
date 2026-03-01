package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestTrustName(t *testing.T) {
	cmd := &TrustCommand{}
	if cmd.Name() != "trust" {
		t.Errorf("expected trust, got %s", cmd.Name())
	}
}

func TestTrustDescription(t *testing.T) {
	cmd := &TrustCommand{}
	if !strings.Contains(cmd.Description(), "T1482") {
		t.Error("description should mention MITRE T1482")
	}
}

func TestTrustEmptyParams(t *testing.T) {
	cmd := &TrustCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("empty params should return error")
	}
}

func TestTrustMissingServer(t *testing.T) {
	cmd := &TrustCommand{}
	result := cmd.Execute(structs.Task{Params: `{}`})
	if result.Status != "error" || !strings.Contains(result.Output, "server") {
		t.Error("missing server should return error mentioning server")
	}
}

func TestTrustBadJSON(t *testing.T) {
	cmd := &TrustCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("bad JSON should return error")
	}
}

func TestTrustParseSID(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name: "standard domain SID S-1-5-21-...",
			input: []byte{
				0x01,                               // revision 1
				0x04,                               // 4 sub-authorities
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority: 5
				0x15, 0x00, 0x00, 0x00, // sub-auth 1: 21
				0x39, 0x05, 0x00, 0x00, // sub-auth 2: 1337
				0xE8, 0x03, 0x00, 0x00, // sub-auth 3: 1000
				0x01, 0x02, 0x00, 0x00, // sub-auth 4: 513
			},
			expected: "S-1-5-21-1337-1000-513",
		},
		{
			name:     "empty",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "too short",
			input:    []byte{0x01, 0x02, 0x03},
			expected: "",
		},
		{
			name: "single sub-authority",
			input: []byte{
				0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x12, 0x00, 0x00, 0x00, // 18 = Local System
			},
			expected: "S-1-5-18",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := trustParseSID(tt.input)
			if result != tt.expected {
				t.Errorf("trustParseSID: expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestTrustDNToDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"DC=north,DC=sevenkingdoms,DC=local", "north.sevenkingdoms.local"},
		{"DC=sevenkingdoms,DC=local", "sevenkingdoms.local"},
		{"DC=essos,DC=local", "essos.local"},
		{"CN=System,DC=corp,DC=com", "corp.com"},
		{"", ""},
		{"OU=Users,OU=Corp", "OU=Users,OU=Corp"}, // no DC components
	}

	for _, tt := range tests {
		result := trustDNToDomain(tt.input)
		if result != tt.expected {
			t.Errorf("trustDNToDomain(%q): expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestTrustDirectionSimple(t *testing.T) {
	tests := []struct {
		dir      int
		expected string
	}{
		{trustDirectionInbound, "Inbound"},
		{trustDirectionOutbound, "Outbound"},
		{trustDirectionBidir, "Bidirectional"},
		{0, "Unknown"},
		{99, "Unknown"},
	}

	for _, tt := range tests {
		result := trustDirectionSimple(tt.dir)
		if !strings.Contains(result, tt.expected) {
			t.Errorf("trustDirectionSimple(%d): expected to contain %q, got %q", tt.dir, tt.expected, result)
		}
	}
}

func TestTrustTypeStr(t *testing.T) {
	tests := []struct {
		typ      int
		expected string
	}{
		{trustTypeDownlevel, "Downlevel"},
		{trustTypeUplevel, "Active Directory"},
		{trustTypeMIT, "MIT"},
		{0, "Unknown"},
		{99, "Unknown"},
	}

	for _, tt := range tests {
		result := trustTypeStr(tt.typ)
		if !strings.Contains(result, tt.expected) {
			t.Errorf("trustTypeStr(%d): expected to contain %q, got %q", tt.typ, tt.expected, result)
		}
	}
}

func TestTrustAttributesStr(t *testing.T) {
	tests := []struct {
		attrs    int
		expected string
	}{
		{0, "None"},
		{trustAttrNonTransitive, "NON_TRANSITIVE"},
		{trustAttrFilterSIDs, "SID_FILTERING"},
		{trustAttrForestTransitive, "FOREST_TRANSITIVE"},
		{trustAttrWithinForest, "WITHIN_FOREST"},
		{trustAttrUsesRC4Encryption, "RC4_ENCRYPTION"},
		{trustAttrUsesAESKeys, "AES_KEYS"},
		{trustAttrWithinForest | trustAttrUsesAESKeys, "WITHIN_FOREST"},
	}

	for _, tt := range tests {
		result := trustAttributesStr(tt.attrs)
		if !strings.Contains(result, tt.expected) {
			t.Errorf("trustAttributesStr(0x%X): expected to contain %q, got %q", tt.attrs, tt.expected, result)
		}
	}

	// Verify combined flags contain both
	combined := trustAttributesStr(trustAttrWithinForest | trustAttrUsesAESKeys)
	if !strings.Contains(combined, "WITHIN_FOREST") || !strings.Contains(combined, "AES_KEYS") {
		t.Errorf("combined flags should contain both WITHIN_FOREST and AES_KEYS, got %q", combined)
	}
}

func TestTrustOutputEntryJSON(t *testing.T) {
	e := trustOutputEntry{
		Partner:    "north.sevenkingdoms.local",
		FlatName:   "NORTH",
		Direction:  "Bidirectional",
		Type:       "Uplevel (Active Directory)",
		Category:   "Intra-Forest",
		Attributes: "WITHIN_FOREST",
		SID:        "S-1-5-21-1234-5678-9012",
		Risk:       "Intra-forest — implicit full trust",
	}
	if e.Partner != "north.sevenkingdoms.local" {
		t.Error("partner should be set")
	}
	if e.Category != "Intra-Forest" {
		t.Error("category should be Intra-Forest")
	}
	if e.Risk == "" {
		t.Error("risk should be set for intra-forest trust")
	}
}

func TestTrustConstants(t *testing.T) {
	// Verify trust attribute constants match Microsoft documentation
	if trustAttrNonTransitive != 0x1 {
		t.Errorf("trustAttrNonTransitive should be 0x1, got 0x%X", trustAttrNonTransitive)
	}
	if trustAttrFilterSIDs != 0x4 {
		t.Errorf("trustAttrFilterSIDs should be 0x4, got 0x%X", trustAttrFilterSIDs)
	}
	if trustAttrForestTransitive != 0x8 {
		t.Errorf("trustAttrForestTransitive should be 0x8, got 0x%X", trustAttrForestTransitive)
	}
	if trustAttrWithinForest != 0x20 {
		t.Errorf("trustAttrWithinForest should be 0x20, got 0x%X", trustAttrWithinForest)
	}
}

func TestTrustDefaultPort(t *testing.T) {
	// Verify default port logic by testing with unreachable server
	cmd := &TrustCommand{}

	// LDAP default should be 389
	result := cmd.Execute(structs.Task{Params: `{"server":"127.0.0.1"}`})
	if result.Status != "error" {
		t.Error("unreachable server should return error")
	}
	if !strings.Contains(result.Output, "389") {
		t.Errorf("default port should be 389 in error message, got: %s", result.Output)
	}

	// LDAPS default should be 636
	result = cmd.Execute(structs.Task{Params: `{"server":"127.0.0.1","use_tls":true}`})
	if result.Status != "error" {
		t.Error("unreachable server should return error")
	}
	if !strings.Contains(result.Output, "636") {
		t.Errorf("TLS default port should be 636 in error message, got: %s", result.Output)
	}
}
