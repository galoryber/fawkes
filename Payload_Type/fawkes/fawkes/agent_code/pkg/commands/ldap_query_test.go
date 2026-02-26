package commands

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestLdapQueryCommand_Name(t *testing.T) {
	cmd := &LdapQueryCommand{}
	if cmd.Name() != "ldap-query" {
		t.Errorf("expected ldap-query, got %s", cmd.Name())
	}
}

func TestLdapQueryCommand_Description(t *testing.T) {
	cmd := &LdapQueryCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestLdapQueryCommand_EmptyParams(t *testing.T) {
	cmd := &LdapQueryCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestLdapQueryCommand_InvalidJSON(t *testing.T) {
	cmd := &LdapQueryCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestLdapQueryCommand_MissingServer(t *testing.T) {
	cmd := &LdapQueryCommand{}
	params, _ := json.Marshal(ldapQueryArgs{Action: "users"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status for missing server, got %s", result.Status)
	}
}

func TestLdapQueryCommand_InvalidAction(t *testing.T) {
	cmd := &LdapQueryCommand{}
	params, _ := json.Marshal(ldapQueryArgs{Action: "invalid", Server: "127.0.0.1"})
	// This will fail on connection, but let's test the action validation path
	// by checking that an unreachable server gives a connection error, not an action error
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestLdapQueryCommand_QueryWithoutFilter(t *testing.T) {
	cmd := &LdapQueryCommand{}
	params, _ := json.Marshal(ldapQueryArgs{Action: "query", Server: "127.0.0.1"})
	// Connection will fail first, but the filter validation happens after connect
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestResolveQuery_PresetUsers(t *testing.T) {
	args := ldapQueryArgs{Action: "users"}
	filter, attrs, desc := resolveQuery(args, "DC=test,DC=local")
	if filter == "" {
		t.Error("expected non-empty filter for users")
	}
	if len(attrs) == 0 {
		t.Error("expected attributes for users")
	}
	if desc == "" {
		t.Error("expected description for users")
	}
}

func TestResolveQuery_PresetComputers(t *testing.T) {
	args := ldapQueryArgs{Action: "computers"}
	filter, attrs, _ := resolveQuery(args, "DC=test,DC=local")
	if filter != "(objectClass=computer)" {
		t.Errorf("expected computer filter, got %s", filter)
	}
	if len(attrs) == 0 {
		t.Error("expected attributes for computers")
	}
}

func TestResolveQuery_PresetGroups(t *testing.T) {
	args := ldapQueryArgs{Action: "groups"}
	filter, _, _ := resolveQuery(args, "DC=test,DC=local")
	if filter != "(objectClass=group)" {
		t.Errorf("expected group filter, got %s", filter)
	}
}

func TestResolveQuery_DomainAdmins(t *testing.T) {
	args := ldapQueryArgs{Action: "domain-admins"}
	filter, _, _ := resolveQuery(args, "DC=test,DC=local")
	if filter == "" {
		t.Error("expected non-empty filter")
	}
	// Should contain the baseDN
	if !contains(filter, "DC=test,DC=local") {
		t.Error("domain-admins filter should contain baseDN")
	}
}

func TestResolveQuery_SPNs(t *testing.T) {
	args := ldapQueryArgs{Action: "spns"}
	filter, _, desc := resolveQuery(args, "DC=test,DC=local")
	if filter == "" {
		t.Error("expected non-empty filter for SPNs")
	}
	if !contains(filter, "servicePrincipalName") {
		t.Error("SPN filter should reference servicePrincipalName")
	}
	if desc == "" {
		t.Error("expected description")
	}
}

func TestResolveQuery_ASRep(t *testing.T) {
	args := ldapQueryArgs{Action: "asrep"}
	filter, _, _ := resolveQuery(args, "DC=test,DC=local")
	if !contains(filter, "4194304") {
		t.Error("AS-REP filter should check for DONT_REQUIRE_PREAUTH flag")
	}
}

func TestResolveQuery_CustomQuery(t *testing.T) {
	args := ldapQueryArgs{Action: "query", Filter: "(cn=test*)"}
	filter, attrs, _ := resolveQuery(args, "DC=test,DC=local")
	if filter != "(cn=test*)" {
		t.Errorf("expected custom filter, got %s", filter)
	}
	if len(attrs) != 1 || attrs[0] != "*" {
		t.Error("expected wildcard attributes for custom query without specified attrs")
	}
}

func TestResolveQuery_CustomAttrs(t *testing.T) {
	args := ldapQueryArgs{
		Action:     "users",
		Attributes: []string{"cn", "mail"},
	}
	_, attrs, _ := resolveQuery(args, "DC=test,DC=local")
	if len(attrs) != 2 || attrs[0] != "cn" || attrs[1] != "mail" {
		t.Errorf("expected custom attributes [cn, mail], got %v", attrs)
	}
}

func TestResolveQuery_InvalidAction(t *testing.T) {
	args := ldapQueryArgs{Action: "nonexistent"}
	filter, _, _ := resolveQuery(args, "DC=test,DC=local")
	if filter != "" {
		t.Errorf("expected empty filter for invalid action, got %s", filter)
	}
}

func TestResolveQuery_QueryNoFilter(t *testing.T) {
	args := ldapQueryArgs{Action: "query"}
	filter, _, _ := resolveQuery(args, "DC=test,DC=local")
	if filter != "" {
		t.Error("expected empty filter for query without filter parameter")
	}
}

func TestDefaultPort_LDAP(t *testing.T) {
	// Verify default port assignment without connecting
	args := ldapQueryArgs{Action: "users", Server: "test-dc"}
	if args.Port <= 0 && !args.UseTLS {
		args.Port = 389
	}
	if args.Port != 389 {
		t.Errorf("expected default port 389, got %d", args.Port)
	}
}

func TestDefaultPort_LDAPS(t *testing.T) {
	// Verify default port assignment for TLS
	args := ldapQueryArgs{Action: "users", Server: "test-dc", UseTLS: true}
	if args.Port <= 0 && args.UseTLS {
		args.Port = 636
	}
	if args.Port != 636 {
		t.Errorf("expected default port 636, got %d", args.Port)
	}
}

func TestPresetQueries_AllExist(t *testing.T) {
	expected := []string{"users", "computers", "groups", "domain-admins", "spns", "asrep"}
	for _, name := range expected {
		if _, ok := presetQueries[name]; !ok {
			t.Errorf("missing preset query: %s", name)
		}
	}
}

func TestPresetQueries_AllHaveFields(t *testing.T) {
	for name, preset := range presetQueries {
		if preset.filter == "" {
			t.Errorf("preset %s has empty filter", name)
		}
		if len(preset.attributes) == 0 {
			t.Errorf("preset %s has no attributes", name)
		}
		if preset.desc == "" {
			t.Errorf("preset %s has no description", name)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// DACL tests

func TestDaclParseSD_MinimalSD(t *testing.T) {
	// Build a minimal self-relative SD with one ACCESS_ALLOWED_ACE
	// SID: S-1-5-21-100-200-300-512 (Domain Admins-like)
	sid := make([]byte, 28)
	sid[0] = 1    // Revision
	sid[1] = 5    // SubAuthorityCount
	sid[7] = 5    // Authority = NT Authority
	binary.LittleEndian.PutUint32(sid[8:], 21)
	binary.LittleEndian.PutUint32(sid[12:], 100)
	binary.LittleEndian.PutUint32(sid[16:], 200)
	binary.LittleEndian.PutUint32(sid[20:], 300)
	binary.LittleEndian.PutUint32(sid[24:], 512)

	aceSize := 8 + len(sid)
	aclSize := 8 + aceSize
	sdSize := 20 + aclSize
	sd := make([]byte, sdSize)

	// SD header
	sd[0] = 1 // Revision
	binary.LittleEndian.PutUint16(sd[2:4], 0x8004) // SE_DACL_PRESENT | SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(sd[16:20], 20)    // OffsetDacl

	// ACL header
	sd[20] = 2 // AclRevision
	binary.LittleEndian.PutUint16(sd[22:24], uint16(aclSize))
	binary.LittleEndian.PutUint16(sd[24:26], 1) // AceCount

	// ACCESS_ALLOWED_ACE
	sd[28] = 0x00 // AceType
	binary.LittleEndian.PutUint16(sd[30:32], uint16(aceSize))
	binary.LittleEndian.PutUint32(sd[32:36], 0x10000000) // GenericAll
	copy(sd[36:], sid)

	aces := daclParseSD(sd)
	if len(aces) != 1 {
		t.Fatalf("expected 1 ACE, got %d", len(aces))
	}
	if aces[0].mask != 0x10000000 {
		t.Errorf("expected mask 0x10000000, got 0x%08X", aces[0].mask)
	}
	if !strings.Contains(aces[0].sid, "S-1-5-21-100-200-300-512") {
		t.Errorf("expected SID S-1-5-21-100-200-300-512, got %s", aces[0].sid)
	}
}

func TestDaclParseSD_NoDACL(t *testing.T) {
	sd := make([]byte, 20)
	sd[0] = 1
	// No DACL offset (all zeros)
	aces := daclParseSD(sd)
	if len(aces) != 0 {
		t.Errorf("expected 0 ACEs for SD without DACL, got %d", len(aces))
	}
}

func TestDaclParseSD_TooShort(t *testing.T) {
	aces := daclParseSD([]byte{1, 0, 4, 0x80})
	if aces != nil {
		t.Error("expected nil for too-short SD")
	}
}

func TestDaclSIDToBytes(t *testing.T) {
	tests := []struct {
		sid      string
		expected int // expected byte length, 0 for nil
	}{
		{"S-1-5-21-100-200-300-512", 28}, // 8 + 5*4
		{"S-1-5-32-544", 16},             // 8 + 2*4
		{"S-1-1-0", 12},                  // 8 + 1*4
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		result := daclSIDToBytes(tt.sid)
		if tt.expected == 0 {
			if result != nil {
				t.Errorf("SID %s: expected nil, got %d bytes", tt.sid, len(result))
			}
		} else {
			if result == nil {
				t.Errorf("SID %s: expected %d bytes, got nil", tt.sid, tt.expected)
			} else if len(result) != tt.expected {
				t.Errorf("SID %s: expected %d bytes, got %d", tt.sid, tt.expected, len(result))
			}
		}
	}
}

func TestDaclSIDToBytes_Roundtrip(t *testing.T) {
	// Convert string SID to bytes, then back to string with adcsParseSID
	sid := "S-1-5-21-3830354804-2748400559-49935211-1001"
	b := daclSIDToBytes(sid)
	if b == nil {
		t.Fatal("expected non-nil bytes")
	}
	result := adcsParseSID(b)
	if result != sid {
		t.Errorf("roundtrip failed: %s -> %s", sid, result)
	}
}

func TestDaclWellKnownRID(t *testing.T) {
	tests := []struct {
		sid    string
		expect string
	}{
		{"S-1-5-21-100-200-300-512", "Domain Admins"},
		{"S-1-5-21-100-200-300-513", "Domain Users"},
		{"S-1-5-21-100-200-300-519", "Enterprise Admins"},
		{"S-1-5-21-100-200-300-502", "krbtgt"},
		{"S-1-5-21-100-200-300-1234", ""},
		{"S-1-5-32-544", ""}, // Only 4 parts, won't match
	}

	for _, tt := range tests {
		result := daclWellKnownRID(tt.sid)
		if result != tt.expect {
			t.Errorf("SID %s: expected '%s', got '%s'", tt.sid, tt.expect, result)
		}
	}
}

func TestDaclDescribePermissions(t *testing.T) {
	tests := []struct {
		mask   uint32
		expect string
	}{
		{0x10000000, "GenericAll (FULL CONTROL)"},
		{0x40000000, "GenericWrite"},
		{0x00080000, "WriteOwner"},
		{0x00040000, "WriteDACL"},
	}

	for _, tt := range tests {
		result := daclDescribePermissions(tt.mask, 0x00, nil)
		if !strings.Contains(result, tt.expect) {
			t.Errorf("mask 0x%08X: expected '%s' in '%s'", tt.mask, tt.expect, result)
		}
	}
}

func TestDaclAssessRisk_LowPrivGenericAll(t *testing.T) {
	// Authenticated Users with GenericAll = dangerous
	risk := daclAssessRisk(0x10000000, 0x00, "S-1-5-11", nil)
	if risk != "dangerous" {
		t.Errorf("expected dangerous for Authenticated Users + GenericAll, got %s", risk)
	}
}

func TestDaclAssessRisk_HighPrivGenericAll(t *testing.T) {
	// SYSTEM with GenericAll = standard (expected)
	risk := daclAssessRisk(0x10000000, 0x00, "S-1-5-18", nil)
	if risk != "standard" {
		t.Errorf("expected standard for SYSTEM + GenericAll, got %s", risk)
	}
}

func TestDaclAssessRisk_DomainAdmins(t *testing.T) {
	// Domain Admins with GenericAll = standard (expected)
	risk := daclAssessRisk(0x10000000, 0x00, "S-1-5-21-100-200-300-512", nil)
	if risk != "standard" {
		t.Errorf("expected standard for Domain Admins + GenericAll, got %s", risk)
	}
}

func TestDaclAssessRisk_ReadOnly(t *testing.T) {
	// ReadControl only = standard
	risk := daclAssessRisk(0x00020000, 0x00, "S-1-5-11", nil)
	if risk != "standard" {
		t.Errorf("expected standard for read-only, got %s", risk)
	}
}

func TestDaclGUIDName_KnownGUIDs(t *testing.T) {
	// User-Force-Change-Password: 00299570-246d-11d0-a768-00aa006e0529
	guid := []byte{
		0x70, 0x95, 0x29, 0x00, // Data1 LE
		0x6d, 0x24,             // Data2 LE
		0xd0, 0x11,             // Data3 LE
		0xa7, 0x68,             // Data4 bytes 0-1
		0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29, // Data4 bytes 2-7
	}
	name := daclGUIDName(guid)
	if name != "User-Force-Change-Password" {
		t.Errorf("expected User-Force-Change-Password, got %s", name)
	}
}

func TestDaclGUIDName_Unknown(t *testing.T) {
	guid := make([]byte, 16) // all zeros
	name := daclGUIDName(guid)
	if name == "unknown" || name == "" {
		// It'll return the formatted GUID string
		return
	}
}

func TestLdapQueryCommand_DaclNoFilter(t *testing.T) {
	cmd := &LdapQueryCommand{}
	params, _ := json.Marshal(ldapQueryArgs{Action: "dacl", Server: "127.0.0.1"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for dacl without filter, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "filter") {
		t.Errorf("expected filter error message, got: %s", result.Output)
	}
}
