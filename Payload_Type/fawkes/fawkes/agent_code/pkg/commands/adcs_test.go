package commands

import (
	"encoding/binary"
	"testing"

	"fawkes/pkg/structs"
)

func TestAdcsResolveEKU(t *testing.T) {
	tests := []struct {
		oid      string
		expected string
	}{
		{oidClientAuth, "Client Authentication"},
		{oidServerAuth, "Server Authentication"},
		{oidAnyPurpose, "Any Purpose"},
		{oidCertRequestAgent, "Certificate Request Agent"},
		{oidSmartCardLogon, "Smart Card Logon"},
		{"1.2.3.4.5.6", "1.2.3.4.5.6"}, // unknown OID
	}

	for _, tt := range tests {
		result := adcsResolveEKU(tt.oid)
		if result != tt.expected {
			t.Errorf("adcsResolveEKU(%q) = %q, want %q", tt.oid, result, tt.expected)
		}
	}
}

func TestAdcsHasAuthEKU(t *testing.T) {
	tests := []struct {
		name     string
		ekus     []string
		expected bool
	}{
		{"empty EKU list (any purpose)", nil, true},
		{"client auth", []string{oidClientAuth}, true},
		{"smart card logon", []string{oidSmartCardLogon}, true},
		{"PKINIT client", []string{oidPKINITClient}, true},
		{"any purpose explicit", []string{oidAnyPurpose}, true},
		{"server auth only", []string{oidServerAuth}, false},
		{"mixed with client auth", []string{oidServerAuth, oidClientAuth}, true},
		{"time stamping only", []string{"1.3.6.1.5.5.7.3.8"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adcsHasAuthEKU(tt.ekus)
			if result != tt.expected {
				t.Errorf("adcsHasAuthEKU(%v) = %v, want %v", tt.ekus, result, tt.expected)
			}
		})
	}
}

func TestAdcsHasAnyPurposeEKU(t *testing.T) {
	if adcsHasAnyPurposeEKU(nil) {
		t.Error("nil should not have any purpose")
	}
	if !adcsHasAnyPurposeEKU([]string{oidAnyPurpose}) {
		t.Error("should detect any purpose OID")
	}
	if adcsHasAnyPurposeEKU([]string{oidClientAuth}) {
		t.Error("client auth is not any purpose")
	}
}

func TestAdcsHasCertRequestAgentEKU(t *testing.T) {
	if adcsHasCertRequestAgentEKU(nil) {
		t.Error("nil should not have cert request agent")
	}
	if !adcsHasCertRequestAgentEKU([]string{oidCertRequestAgent}) {
		t.Error("should detect cert request agent OID")
	}
	if adcsHasCertRequestAgentEKU([]string{oidClientAuth}) {
		t.Error("client auth is not cert request agent")
	}
}

func TestGuidToBytes(t *testing.T) {
	// Test the enrollment GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55
	b := guidToBytes("0e10c968-78fb-11d2-90d4-00c04f79dc55")
	if len(b) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(b))
	}

	// Data1: 0e10c968 → LE: 68 c9 10 0e
	if b[0] != 0x68 || b[1] != 0xc9 || b[2] != 0x10 || b[3] != 0x0e {
		t.Errorf("Data1 wrong: %x", b[0:4])
	}
	// Data2: 78fb → LE: fb 78
	if b[4] != 0xfb || b[5] != 0x78 {
		t.Errorf("Data2 wrong: %x", b[4:6])
	}
	// Data3: 11d2 → LE: d2 11
	if b[6] != 0xd2 || b[7] != 0x11 {
		t.Errorf("Data3 wrong: %x", b[6:8])
	}
	// Data4: 90d400c04f79dc55 → BE
	if b[8] != 0x90 || b[9] != 0xd4 || b[14] != 0xdc || b[15] != 0x55 {
		t.Errorf("Data4 wrong: %x", b[8:16])
	}

	// Invalid GUID
	if guidToBytes("invalid") != nil {
		t.Error("should return nil for invalid GUID")
	}
}

func TestAdcsMatchGUID(t *testing.T) {
	a := guidToBytes("0e10c968-78fb-11d2-90d4-00c04f79dc55")
	b := guidToBytes("0e10c968-78fb-11d2-90d4-00c04f79dc55")
	c := guidToBytes("a05b8cc2-17bc-4802-a710-e7c15ab866a2")

	if !adcsMatchGUID(a, b) {
		t.Error("identical GUIDs should match")
	}
	if adcsMatchGUID(a, c) {
		t.Error("different GUIDs should not match")
	}
	if adcsMatchGUID(nil, b) {
		t.Error("nil should not match")
	}
	if adcsMatchGUID(a, []byte{1, 2, 3}) {
		t.Error("short slice should not match")
	}
}

func TestAdcsParseSID(t *testing.T) {
	// Build SID for S-1-5-21-100-200-300-513 (Domain Users)
	sid := buildTestSID(1, 5, []uint32{21, 100, 200, 300, 513})
	result := adcsParseSID(sid)
	if result != "S-1-5-21-100-200-300-513" {
		t.Errorf("expected S-1-5-21-100-200-300-513, got %s", result)
	}

	// S-1-1-0 (Everyone)
	sid = buildTestSID(1, 1, []uint32{0})
	result = adcsParseSID(sid)
	if result != "S-1-1-0" {
		t.Errorf("expected S-1-1-0, got %s", result)
	}

	// S-1-5-11 (Authenticated Users)
	sid = buildTestSID(1, 5, []uint32{11})
	result = adcsParseSID(sid)
	if result != "S-1-5-11" {
		t.Errorf("expected S-1-5-11, got %s", result)
	}

	// Too short
	if adcsParseSID([]byte{1, 2}) != "" {
		t.Error("short input should return empty")
	}
	if adcsParseSID(nil) != "" {
		t.Error("nil should return empty")
	}
}

// buildTestSID constructs a binary SID
func buildTestSID(revision byte, authority uint64, subAuthorities []uint32) []byte {
	b := make([]byte, 8+len(subAuthorities)*4)
	b[0] = revision
	b[1] = byte(len(subAuthorities))
	// Authority (6 bytes, big-endian)
	for i := 5; i >= 0; i-- {
		b[2+(5-i)] = byte(authority >> (uint(i) * 8))
	}
	for i, sa := range subAuthorities {
		binary.LittleEndian.PutUint32(b[8+i*4:], sa)
	}
	return b
}

func TestAdcsFilterLowPriv(t *testing.T) {
	tests := []struct {
		name     string
		sids     []string
		expected int
	}{
		{"Everyone", []string{"S-1-1-0"}, 1},
		{"Authenticated Users", []string{"S-1-5-11"}, 1},
		{"BUILTIN\\Users", []string{"S-1-5-32-545"}, 1},
		{"Domain Users (RID 513)", []string{"S-1-5-21-100-200-300-513"}, 1},
		{"Domain Computers (RID 515)", []string{"S-1-5-21-100-200-300-515"}, 1},
		{"Domain Admins (RID 512) - not low priv", []string{"S-1-5-21-100-200-300-512"}, 0},
		{"SYSTEM - not low priv", []string{"S-1-5-18"}, 0},
		{"mixed", []string{"S-1-1-0", "S-1-5-18", "S-1-5-21-1-2-3-513"}, 2},
		{"empty", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adcsFilterLowPriv(tt.sids)
			if len(result) != tt.expected {
				t.Errorf("expected %d results, got %d: %v", tt.expected, len(result), result)
			}
		})
	}
}

func TestAdcsParseSD(t *testing.T) {
	// Test with nil/empty
	if aces := adcsParseSD(nil); len(aces) != 0 {
		t.Error("nil SD should return no ACEs")
	}
	if aces := adcsParseSD([]byte{1, 2, 3}); len(aces) != 0 {
		t.Error("short SD should return no ACEs")
	}

	// Build a minimal SD with one ACCESS_ALLOWED_ACE granting GenericAll to Everyone (S-1-1-0)
	sd := buildTestSD([]testACE{
		{aceType: 0x00, mask: adsGenericAll, sid: buildTestSID(1, 1, []uint32{0})},
	})
	aces := adcsParseSD(sd)
	if len(aces) != 1 {
		t.Fatalf("expected 1 ACE, got %d", len(aces))
	}
	if aces[0].sid != "S-1-1-0" {
		t.Errorf("expected S-1-1-0, got %s", aces[0].sid)
	}
	if aces[0].mask != adsGenericAll {
		t.Errorf("expected GenericAll mask, got 0x%X", aces[0].mask)
	}
}

func TestAdcsParseEnrollmentPerms(t *testing.T) {
	// SD with GenericAll for Everyone
	sd := buildTestSD([]testACE{
		{aceType: 0x00, mask: adsGenericAll, sid: buildTestSID(1, 1, []uint32{0})},
	})
	perms := adcsParseEnrollmentPerms(sd)
	if len(perms) != 1 || perms[0] != "S-1-1-0" {
		t.Errorf("expected [S-1-1-0], got %v", perms)
	}

	// SD with DS_CONTROL_ACCESS (all extended rights) for Authenticated Users
	sd = buildTestSD([]testACE{
		{aceType: 0x00, mask: adsRightDSControlAccess, sid: buildTestSID(1, 5, []uint32{11})},
	})
	perms = adcsParseEnrollmentPerms(sd)
	if len(perms) != 1 || perms[0] != "S-1-5-11" {
		t.Errorf("expected [S-1-5-11], got %v", perms)
	}
}

func TestAdcsParseWritePerms(t *testing.T) {
	// SD with WriteDACL for Domain Users
	domainUsersSID := buildTestSID(1, 5, []uint32{21, 100, 200, 300, 513})
	sd := buildTestSD([]testACE{
		{aceType: 0x00, mask: adsWriteDACL, sid: domainUsersSID},
	})
	perms := adcsParseWritePerms(sd)
	if len(perms) != 1 {
		t.Fatalf("expected 1 writer, got %d", len(perms))
	}
	if perms[0] != "S-1-5-21-100-200-300-513" {
		t.Errorf("expected Domain Users SID, got %s", perms[0])
	}
}

func TestAdcsParseObjectACE(t *testing.T) {
	// Build SD with ACCESS_ALLOWED_OBJECT_ACE (type 0x05) for enrollment right
	enrollGUID := guidToBytes("0e10c968-78fb-11d2-90d4-00c04f79dc55")
	authUsersSID := buildTestSID(1, 5, []uint32{11})

	sd := buildTestSD([]testACE{
		{
			aceType:    0x05,
			mask:       adsRightDSControlAccess,
			sid:        authUsersSID,
			objectGUID: enrollGUID,
		},
	})

	perms := adcsParseEnrollmentPerms(sd)
	if len(perms) != 1 || perms[0] != "S-1-5-11" {
		t.Errorf("expected [S-1-5-11] for enrollment right, got %v", perms)
	}

	// Non-enrollment GUID should not match
	otherGUID := guidToBytes("a05b8cc2-17bc-4802-a710-e7c15ab866a2")
	sd = buildTestSD([]testACE{
		{
			aceType:    0x05,
			mask:       adsRightDSControlAccess,
			sid:        authUsersSID,
			objectGUID: otherGUID,
		},
	})
	perms = adcsParseEnrollmentPerms(sd)
	if len(perms) != 0 {
		t.Errorf("non-enrollment GUID should not match, got %v", perms)
	}
}

func TestAdcsCommandEmptyParams(t *testing.T) {
	cmd := &AdcsCommand{}

	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("empty params should return error")
	}

	result = cmd.Execute(structs.Task{Params: `{"action":"find"}`})
	if result.Status != "error" || !contains(result.Output, "server") {
		t.Error("missing server should return error mentioning server")
	}

	result = cmd.Execute(structs.Task{Params: `{"action":"bad","server":"1.2.3.4"}`})
	// This will fail to connect, but let's test the JSON parsing
	if result.Status != "error" {
		t.Error("expected error (can't connect to 1.2.3.4)")
	}
}

func TestAdcsCommandInvalidAction(t *testing.T) {
	cmd := &AdcsCommand{}
	// Bad JSON
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("bad JSON should return error")
	}
}

// Helper types and functions for building test security descriptors
type testACE struct {
	aceType    byte
	mask       uint32
	sid        []byte
	objectGUID []byte // only for type 0x05
}

func buildTestSD(aces []testACE) []byte {
	// Build DACL
	dacl := buildTestDACL(aces)

	// SD header (20 bytes)
	sd := make([]byte, 20+len(dacl))
	sd[0] = 1                        // Revision
	binary.LittleEndian.PutUint16(sd[2:4], 0x8004) // Control: SE_DACL_PRESENT | SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(sd[16:20], 20)    // DACL offset

	copy(sd[20:], dacl)
	return sd
}

func buildTestDACL(aces []testACE) []byte {
	// Build ACE bytes first
	var aceBytes []byte
	for _, ace := range aces {
		aceBytes = append(aceBytes, buildTestACEBytes(ace)...)
	}

	// ACL header (8 bytes)
	aclSize := 8 + len(aceBytes)
	acl := make([]byte, aclSize)
	acl[0] = 2 // Revision
	binary.LittleEndian.PutUint16(acl[2:4], uint16(aclSize))
	binary.LittleEndian.PutUint16(acl[4:6], uint16(len(aces)))

	copy(acl[8:], aceBytes)
	return acl
}

func buildTestACEBytes(ace testACE) []byte {
	switch ace.aceType {
	case 0x00: // ACCESS_ALLOWED_ACE
		size := 4 + 4 + len(ace.sid) // header(4) + mask(4) + SID
		b := make([]byte, size)
		b[0] = ace.aceType
		binary.LittleEndian.PutUint16(b[2:4], uint16(size))
		binary.LittleEndian.PutUint32(b[4:8], ace.mask)
		copy(b[8:], ace.sid)
		return b

	case 0x05: // ACCESS_ALLOWED_OBJECT_ACE
		// header(4) + mask(4) + flags(4) + objectGUID(16) + SID
		var flags uint32
		guidLen := 0
		if len(ace.objectGUID) == 16 {
			flags |= 0x01 // ACE_OBJECT_TYPE_PRESENT
			guidLen = 16
		}
		size := 4 + 4 + 4 + guidLen + len(ace.sid)
		b := make([]byte, size)
		b[0] = ace.aceType
		binary.LittleEndian.PutUint16(b[2:4], uint16(size))
		binary.LittleEndian.PutUint32(b[4:8], ace.mask)
		binary.LittleEndian.PutUint32(b[8:12], flags)
		offset := 12
		if guidLen > 0 {
			copy(b[offset:], ace.objectGUID)
			offset += 16
		}
		copy(b[offset:], ace.sid)
		return b
	}
	return nil
}

// contains is already defined in ldap_query_test.go (same package)
