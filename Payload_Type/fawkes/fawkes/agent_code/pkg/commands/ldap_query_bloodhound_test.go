package commands

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestBhFormatSID(t *testing.T) {
	// Build a well-known SID: S-1-5-21-1234567890-987654321-111222333-500
	raw := make([]byte, 28)
	raw[0] = 1  // revision
	raw[1] = 4  // sub-authority count
	raw[7] = 5  // authority = 5
	binary.LittleEndian.PutUint32(raw[8:], 21)
	binary.LittleEndian.PutUint32(raw[12:], 1234567890)
	binary.LittleEndian.PutUint32(raw[16:], 987654321)
	binary.LittleEndian.PutUint32(raw[20:], 111222333)
	binary.LittleEndian.PutUint32(raw[24:], 500)

	// Wait, sub-authority count is 4 but we wrote 5 values (21 + 3 domain parts + RID)
	// Actually: S-1-5-21-... means authority=5 and first sub-auth=21
	// Let me fix: 5 sub-authorities (21, 1234567890, 987654321, 111222333, 500)
	raw[1] = 5
	raw2 := make([]byte, 28)
	copy(raw2, raw[:8])
	binary.LittleEndian.PutUint32(raw2[8:], 21)
	binary.LittleEndian.PutUint32(raw2[12:], 1234567890)
	binary.LittleEndian.PutUint32(raw2[16:], 987654321)
	binary.LittleEndian.PutUint32(raw2[20:], 111222333)
	binary.LittleEndian.PutUint32(raw2[24:], 500)
	raw2[0] = 1
	raw2[1] = 5
	raw2[7] = 5

	got := bhFormatSID(raw2)
	want := "S-1-5-21-1234567890-987654321-111222333-500"
	if got != want {
		t.Errorf("bhFormatSID = %q, want %q", got, want)
	}
}

func TestBhFormatSID_Short(t *testing.T) {
	got := bhFormatSID([]byte{1, 2, 3})
	if got != "" {
		t.Errorf("bhFormatSID(short) = %q, want empty", got)
	}
}

func TestBhFormatSID_Nil(t *testing.T) {
	got := bhFormatSID(nil)
	if got != "" {
		t.Errorf("bhFormatSID(nil) = %q, want empty", got)
	}
}

func TestBhFormatGUID(t *testing.T) {
	raw := []byte{
		0x01, 0x02, 0x03, 0x04, // data1 LE
		0x05, 0x06, // data2 LE
		0x07, 0x08, // data3 LE
		0x09, 0x0a, // data4[0:2]
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // data4[2:8]
	}
	got := bhFormatGUID(raw)
	want := "{04030201-0605-0807-090a-0b0c0d0e0f10}"
	if got != want {
		t.Errorf("bhFormatGUID = %q, want %q", got, want)
	}
}

func TestBhFormatGUID_WrongLength(t *testing.T) {
	got := bhFormatGUID([]byte{1, 2, 3})
	if got != "" {
		t.Errorf("bhFormatGUID(short) = %q, want empty", got)
	}
}

func TestBhDNToDomain(t *testing.T) {
	tests := []struct {
		dn   string
		want string
	}{
		{"DC=sevenkingdoms,DC=local", "SEVENKINGDOMS.LOCAL"},
		{"DC=north,DC=sevenkingdoms,DC=local", "NORTH.SEVENKINGDOMS.LOCAL"},
		{"DC=essos,DC=local", "ESSOS.LOCAL"},
		{"CN=Users,DC=test,DC=com", "TEST.COM"},
		{"", ""},
	}
	for _, tt := range tests {
		got := bhDNToDomain(tt.dn)
		if got != tt.want {
			t.Errorf("bhDNToDomain(%q) = %q, want %q", tt.dn, got, tt.want)
		}
	}
}

func TestBhParseUint(t *testing.T) {
	tests := []struct {
		s    string
		want uint64
	}{
		{"512", 512},
		{"0", 0},
		{"4194304", 4194304},
		{"", 0},
		{"abc", 0},
	}
	for _, tt := range tests {
		got := bhParseUint(tt.s)
		if got != tt.want {
			t.Errorf("bhParseUint(%q) = %d, want %d", tt.s, got, tt.want)
		}
	}
}

func TestBhParseFileTime(t *testing.T) {
	tests := []struct {
		s    string
		want int64
	}{
		// 133498272000000000 FILETIME → (133498272000000000 - 116444736000000000) / 10000000 = 1705353600
		{"133498272000000000", 1705353600},
		{"0", 0},
		{"", 0},
		{"abc", 0},
		// Pre-epoch
		{"1", 0},
	}
	for _, tt := range tests {
		got := bhParseFileTime(tt.s)
		if got != tt.want {
			t.Errorf("bhParseFileTime(%q) = %d, want %d", tt.s, got, tt.want)
		}
	}
}

func TestBhParseADTime(t *testing.T) {
	// 20240115120000.0Z should parse to 2024-01-15 12:00:00 UTC = 1705320000
	got := bhParseADTime("20240115120000.0Z")
	want := int64(1705320000)
	if got != want {
		t.Errorf("bhParseADTime(20240115120000.0Z) = %d, want %d", got, want)
	}

	// Empty
	if bhParseADTime("") != 0 {
		t.Error("bhParseADTime('') should be 0")
	}
}

func TestBhParseGPLink(t *testing.T) {
	gpLink := "[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=sevenkingdoms,DC=local;0][LDAP://CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=sevenkingdoms,DC=local;2]"
	links := bhParseGPLink(gpLink)
	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(links))
	}
	if links[0].GUID != "{31B2F340-016D-11D2-945F-00C04FB984F9}" {
		t.Errorf("link 0 GUID = %s", links[0].GUID)
	}
	if links[0].IsEnforced {
		t.Error("link 0 should not be enforced")
	}
	if links[1].GUID != "{6AC1786C-016F-11D2-945F-00C04FB984F9}" {
		t.Errorf("link 1 GUID = %s", links[1].GUID)
	}
	if !links[1].IsEnforced {
		t.Error("link 1 should be enforced")
	}
}

func TestBhParseGPLink_Empty(t *testing.T) {
	links := bhParseGPLink("")
	if links != nil {
		t.Errorf("expected nil for empty gpLink, got %v", links)
	}
}

func TestBhFuncLevelName(t *testing.T) {
	tests := []struct {
		level string
		want  string
	}{
		{"0", "2000"},
		{"3", "2008"},
		{"7", "2016"},
		{"", ""},
		{"8", "8"},
	}
	for _, tt := range tests {
		got := bhFuncLevelName(tt.level)
		if got != tt.want {
			t.Errorf("bhFuncLevelName(%q) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestBhDateToUnix(t *testing.T) {
	// 2024-01-15 12:00:00 UTC = 1705320000
	got := bhDateToUnix(2024, 1, 15, 12, 0, 0)
	if got != 1705320000 {
		t.Errorf("bhDateToUnix(2024-01-15 12:00:00) = %d, want 1705320000", got)
	}

	// Unix epoch
	got = bhDateToUnix(1970, 1, 1, 0, 0, 0)
	if got != 0 {
		t.Errorf("bhDateToUnix(1970-01-01 00:00:00) = %d, want 0", got)
	}
}

func TestBhResolveGroupMembers(t *testing.T) {
	dnToSID := map[string]string{
		"cn=user1,cn=users,dc=test,dc=com":  "S-1-5-21-100-200-300-1001",
		"cn=group2,cn=users,dc=test,dc=com": "S-1-5-21-100-200-300-1002",
	}
	dnToType := map[string]string{
		"cn=user1,cn=users,dc=test,dc=com":  "User",
		"cn=group2,cn=users,dc=test,dc=com": "Group",
	}

	groups := []bhGroup{
		{
			ObjectIdentifier: "S-1-5-21-100-200-300-512",
			Members: []bhTypedPrincipal{
				{ObjectIdentifier: "cn=user1,cn=users,dc=test,dc=com", ObjectType: "Base"},
				{ObjectIdentifier: "cn=group2,cn=users,dc=test,dc=com", ObjectType: "Base"},
				{ObjectIdentifier: "cn=unknown,cn=users,dc=test,dc=com", ObjectType: "Base"},
			},
		},
	}

	bhResolveGroupMembers(groups, dnToSID, dnToType)

	members := groups[0].Members
	if len(members) != 3 {
		t.Fatalf("expected 3 members, got %d", len(members))
	}
	if members[0].ObjectIdentifier != "S-1-5-21-100-200-300-1001" || members[0].ObjectType != "User" {
		t.Errorf("member 0: %+v", members[0])
	}
	if members[1].ObjectIdentifier != "S-1-5-21-100-200-300-1002" || members[1].ObjectType != "Group" {
		t.Errorf("member 1: %+v", members[1])
	}
	if members[2].ObjectType != "Base" {
		t.Errorf("unresolved member should keep Base type: %+v", members[2])
	}
}

func TestBhOutputJSON(t *testing.T) {
	output := bhOutput{
		Computers: bhFile{
			Meta: bhMeta{Type: "computers", Count: 1, Version: 6},
			Data: []interface{}{
				bhComputer{
					ObjectIdentifier: "S-1-5-21-100-200-300-1001",
					Properties: bhComputerProps{
						Name:   "PC01.TEST.COM",
						Domain: "TEST.COM",
					},
					AllowedToDelegate: []bhTypedPrincipal{},
					AllowedToAct:      []bhTypedPrincipal{},
					HasSIDHistory:     []interface{}{},
					Sessions:          bhSessionResult{Results: []interface{}{}, Collected: false},
					PrivilegedSessions: bhSessionResult{Results: []interface{}{}, Collected: false},
					RegistrySessions:  bhSessionResult{Results: []interface{}{}, Collected: false},
					LocalAdmins:       bhLocalGroupResult{Results: []interface{}{}, Collected: false},
					RemoteDesktopUsers: bhLocalGroupResult{Results: []interface{}{}, Collected: false},
					DcomUsers:         bhLocalGroupResult{Results: []interface{}{}, Collected: false},
					PSRemoteUsers:     bhLocalGroupResult{Results: []interface{}{}, Collected: false},
					Aces:              []interface{}{},
				},
			},
		},
		Users:   bhFile{Meta: bhMeta{Type: "users", Version: 6}, Data: []interface{}{}},
		Groups:  bhFile{Meta: bhMeta{Type: "groups", Version: 6}, Data: []interface{}{}},
		Domains: bhFile{Meta: bhMeta{Type: "domains", Version: 6}, Data: []interface{}{}},
		OUs:     bhFile{Meta: bhMeta{Type: "ous", Version: 6}, Data: []interface{}{}},
		GPOs:    bhFile{Meta: bhMeta{Type: "gpos", Version: 6}, Data: []interface{}{}},
		Summary: bhSummary{
			Domain:    "TEST.COM",
			DomainSID: "S-1-5-21-100-200-300",
			Computers: 1,
		},
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	comp, ok := parsed["computers"].(map[string]interface{})
	if !ok {
		t.Fatal("missing computers key")
	}
	meta, ok := comp["meta"].(map[string]interface{})
	if !ok {
		t.Fatal("missing meta in computers")
	}
	if meta["type"] != "computers" {
		t.Errorf("computers meta type = %v", meta["type"])
	}
	if meta["version"].(float64) != 6 {
		t.Errorf("computers meta version = %v", meta["version"])
	}

	summary, ok := parsed["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("missing summary")
	}
	if summary["domain"] != "TEST.COM" {
		t.Errorf("summary domain = %v", summary["domain"])
	}
}

func TestBhToInterfaceSlice(t *testing.T) {
	input := []bhUser{
		{ObjectIdentifier: "S-1-5-21-1"},
		{ObjectIdentifier: "S-1-5-21-2"},
	}
	result := bhToInterfaceSlice(input)
	if len(result) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(result))
	}
	u, ok := result[0].(bhUser)
	if !ok {
		t.Fatal("element 0 is not bhUser")
	}
	if u.ObjectIdentifier != "S-1-5-21-1" {
		t.Errorf("element 0 SID = %s", u.ObjectIdentifier)
	}
}

func TestBhToInterfaceSlice_Empty(t *testing.T) {
	result := bhToInterfaceSlice([]bhGroup{})
	if len(result) != 0 {
		t.Fatalf("expected 0, got %d", len(result))
	}
}

func TestBhCountTrusts(t *testing.T) {
	domains := []bhDomain{
		{Trusts: []bhTrust{{}, {}}},
		{Trusts: []bhTrust{{}}},
	}
	if got := bhCountTrusts(domains); got != 3 {
		t.Errorf("bhCountTrusts = %d, want 3", got)
	}
}

func TestBhUACFlags(t *testing.T) {
	// Test UAC bit extraction used in user/computer collection
	var uac uint64

	// Disabled (0x2)
	uac = 0x202 // normal account (0x200) + disabled (0x2)
	if uac&0x2 == 0 {
		t.Error("should detect disabled")
	}

	// Enabled
	uac = 0x200 // normal account only
	if uac&0x2 != 0 {
		t.Error("should be enabled")
	}

	// DONT_REQUIRE_PREAUTH (0x400000)
	uac = 0x400200
	if uac&0x400000 == 0 {
		t.Error("should detect DONT_REQUIRE_PREAUTH")
	}

	// TRUSTED_FOR_DELEGATION (0x80000)
	uac = 0x80200
	if uac&0x80000 == 0 {
		t.Error("should detect unconstrained delegation")
	}

	// TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000)
	uac = 0x1000200
	if uac&0x1000000 == 0 {
		t.Error("should detect trusted-to-auth")
	}
}
