package commands

import (
	"strings"
	"testing"
)

// TestDaclSIDToBytesErrors covers the error paths in daclSIDToBytes.
func TestDaclSIDToBytesErrors(t *testing.T) {
	t.Run("non-numeric revision", func(t *testing.T) {
		result := daclSIDToBytes("S-X-5-21-1-2-3-4")
		if result != nil {
			t.Error("expected nil for non-numeric revision")
		}
	})

	t.Run("non-numeric authority", func(t *testing.T) {
		result := daclSIDToBytes("S-1-BADAUTH-21-1-2-3-4")
		if result != nil {
			t.Error("expected nil for non-numeric authority")
		}
	})

	t.Run("non-numeric sub-authority", func(t *testing.T) {
		result := daclSIDToBytes("S-1-5-21-BAD-2-3-4")
		if result != nil {
			t.Error("expected nil for non-numeric sub-authority")
		}
	})
}

// TestDaclWellKnownRIDExtra covers the RIDs not tested in the main test file.
func TestDaclWellKnownRIDExtra(t *testing.T) {
	cases := []struct {
		sid  string
		want string
	}{
		{"S-1-5-21-1-2-3-514", "Domain Guests"},
		{"S-1-5-21-1-2-3-515", "Domain Computers"},
		{"S-1-5-21-1-2-3-517", "Cert Publishers"},
		{"S-1-5-21-1-2-3-519", "Enterprise Admins"},
		{"S-1-5-21-1-2-3-520", "Group Policy Creator Owners"},
		{"S-1-5-21-1-2-3-527", "Enterprise Key Admins"},
		{"S-1-5-21-1-2-3-553", "RAS and IAS Servers"},
		{"S-1-5-21-1-2-3-571", "Allowed RODC Password Replication Group"},
		{"S-1-5-21-1-2-3-572", "Denied RODC Password Replication Group"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got := daclWellKnownRID(tc.sid)
			if got != tc.want {
				t.Errorf("daclWellKnownRID(%q) = %q, want %q", tc.sid, got, tc.want)
			}
		})
	}
}

// TestDaclGUIDNameEdgeCases covers non-16-byte and unknown GUID paths.
func TestDaclGUIDNameEdgeCases(t *testing.T) {
	t.Run("non-16-byte input returns 'unknown'", func(t *testing.T) {
		got := daclGUIDName([]byte{0x01, 0x02, 0x03})
		if got != "unknown" {
			t.Errorf("got %q, want 'unknown' for short GUID", got)
		}
	})

	t.Run("empty input returns 'unknown'", func(t *testing.T) {
		got := daclGUIDName([]byte{})
		if got != "unknown" {
			t.Errorf("got %q, want 'unknown' for empty GUID", got)
		}
	})

	t.Run("unknown 16-byte GUID returns GUID string", func(t *testing.T) {
		// A random GUID not in the known list
		guid := make([]byte, 16) // all zeros GUID
		got := daclGUIDName(guid)
		// Should return the formatted GUID string, not a known name
		if got == "unknown" {
			t.Error("16-byte input should not return 'unknown'")
		}
		if len(got) == 0 {
			t.Error("should return GUID string for unknown GUID")
		}
	})
}

// TestDaclAssessRiskExtra covers the lowPrivSIDs domain user/computer paths.
func TestDaclAssessRiskExtra(t *testing.T) {
	t.Run("Domain Users (513) with WriteDACL is dangerous", func(t *testing.T) {
		got := daclAssessRisk(0x00040000, 0, "S-1-5-21-1-2-3-513", nil)
		if got != "dangerous" {
			t.Errorf("Domain Users WriteDACL = %q, want dangerous", got)
		}
	})

	t.Run("Domain Computers (515) with WriteOwner is dangerous", func(t *testing.T) {
		got := daclAssessRisk(0x00080000, 0, "S-1-5-21-1-2-3-515", nil)
		if got != "dangerous" {
			t.Errorf("Domain Computers WriteOwner = %q, want dangerous", got)
		}
	})
}

// TestDaclDescribePermissionsExtra covers the uncovered bit paths.
func TestDaclDescribePermissionsExtra(t *testing.T) {
	t.Run("GenericRead", func(t *testing.T) {
		got := daclDescribePermissions(0x80000000, 0, nil)
		if !strings.Contains(got, "GenericRead") {
			t.Errorf("got %q, want GenericRead", got)
		}
	})

	t.Run("GenericWrite", func(t *testing.T) {
		got := daclDescribePermissions(0x40000000, 0, nil)
		if !strings.Contains(got, "GenericWrite") {
			t.Errorf("got %q, want GenericWrite", got)
		}
	})

	t.Run("GenericExecute", func(t *testing.T) {
		got := daclDescribePermissions(0x20000000, 0, nil)
		if !strings.Contains(got, "GenericExecute") {
			t.Errorf("got %q, want GenericExecute", got)
		}
	})

	t.Run("StandardAll", func(t *testing.T) {
		// 0x000F0000 = all 4 standard rights at once → StandardAll
		got := daclDescribePermissions(0x000F0000, 0, nil)
		if !strings.Contains(got, "StandardAll") {
			t.Errorf("got %q, want StandardAll", got)
		}
	})

	t.Run("ReadControl", func(t *testing.T) {
		got := daclDescribePermissions(0x00020000, 0, nil)
		if !strings.Contains(got, "ReadControl") {
			t.Errorf("got %q, want ReadControl", got)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		got := daclDescribePermissions(0x00010000, 0, nil)
		if !strings.Contains(got, "Delete") {
			t.Errorf("got %q, want Delete", got)
		}
	})

	t.Run("WriteProperty with GUID", func(t *testing.T) {
		// Self-Membership GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
		// Bytes (LE for first 3 groups): c0 79 96 bf | e6 0d | d0 11 | a2 85 | 00 aa 00 30 49 e2
		guid := []byte{0xc0, 0x79, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
		got := daclDescribePermissions(0x00000020, 0x05, guid)
		if !strings.Contains(got, "WriteProperty") {
			t.Errorf("got %q, want WriteProperty", got)
		}
	})

	t.Run("WriteAllProperties (no GUID)", func(t *testing.T) {
		got := daclDescribePermissions(0x00000020, 0, nil)
		if !strings.Contains(got, "WriteAllProperties") {
			t.Errorf("got %q, want WriteAllProperties", got)
		}
	})

	t.Run("ReadProperty", func(t *testing.T) {
		got := daclDescribePermissions(0x00000010, 0, nil)
		if !strings.Contains(got, "ReadProperty") {
			t.Errorf("got %q, want ReadProperty", got)
		}
	})

	t.Run("ListObject", func(t *testing.T) {
		got := daclDescribePermissions(0x00000008, 0, nil)
		if !strings.Contains(got, "ListObject") {
			t.Errorf("got %q, want ListObject", got)
		}
	})

	t.Run("ListChildren", func(t *testing.T) {
		got := daclDescribePermissions(0x00000001, 0, nil)
		if !strings.Contains(got, "ListChildren") {
			t.Errorf("got %q, want ListChildren", got)
		}
	})

	t.Run("combined GenericRead+WriteOwner+AllExtendedRights", func(t *testing.T) {
		got := daclDescribePermissions(0x80080100, 0, nil)
		if !strings.Contains(got, "GenericRead") {
			t.Errorf("got %q, want GenericRead", got)
		}
		if !strings.Contains(got, "WriteOwner") {
			t.Errorf("got %q, want WriteOwner", got)
		}
		if !strings.Contains(got, "AllExtendedRights") {
			t.Errorf("got %q, want AllExtendedRights", got)
		}
	})
}
