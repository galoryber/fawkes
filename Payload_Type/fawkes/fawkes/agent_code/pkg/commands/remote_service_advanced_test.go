package commands

import (
	"testing"
)

func TestParseTriggerType_DomainJoin(t *testing.T) {
	variants := []string{"domain-join", "domain_join", "domainjoin"}
	for _, v := range variants {
		typ, guid, desc := parseTriggerType(v)
		if typ != svcTriggerTypeDomainJoin {
			t.Errorf("parseTriggerType(%q): expected domain join type, got %d", v, typ)
		}
		if guid == nil {
			t.Errorf("parseTriggerType(%q): expected non-nil GUID", v)
		}
		if desc == "" {
			t.Errorf("parseTriggerType(%q): expected description", v)
		}
	}
}

func TestParseTriggerType_Firewall(t *testing.T) {
	variants := []string{"firewall", "firewall-open", "firewall_open"}
	for _, v := range variants {
		typ, guid, desc := parseTriggerType(v)
		if typ != svcTriggerTypeFirewall {
			t.Errorf("parseTriggerType(%q): expected firewall type, got %d", v, typ)
		}
		if guid == nil {
			t.Errorf("parseTriggerType(%q): expected non-nil GUID", v)
		}
		if desc == "" {
			t.Errorf("parseTriggerType(%q): expected description", v)
		}
	}
}

func TestParseTriggerType_GroupPolicy(t *testing.T) {
	variants := []string{"group-policy", "group_policy", "grouppolicy", "gpo"}
	for _, v := range variants {
		typ, guid, _ := parseTriggerType(v)
		if typ != svcTriggerTypeGroupPolicy {
			t.Errorf("parseTriggerType(%q): expected group policy type, got %d", v, typ)
		}
		if guid == nil {
			t.Errorf("parseTriggerType(%q): expected non-nil GUID", v)
		}
	}
}

func TestParseTriggerType_Default(t *testing.T) {
	// Unknown input should default to network availability
	inputs := []string{"", "unknown", "random", "network"}
	for _, v := range inputs {
		typ, guid, desc := parseTriggerType(v)
		if typ != svcTriggerTypeIPAddress {
			t.Errorf("parseTriggerType(%q): expected IP address type (default), got %d", v, typ)
		}
		if guid == nil {
			t.Errorf("parseTriggerType(%q): expected non-nil GUID", v)
		}
		if desc == "" {
			t.Errorf("parseTriggerType(%q): expected description", v)
		}
	}
}

func TestParseTriggerType_CaseInsensitive(t *testing.T) {
	typ, _, _ := parseTriggerType("DOMAIN-JOIN")
	if typ != svcTriggerTypeDomainJoin {
		t.Errorf("parseTriggerType should be case-insensitive")
	}
}

func TestEncodeRegSZ_Simple(t *testing.T) {
	result := encodeRegSZ("AB")
	expected := []byte{'A', 0, 'B', 0, 0, 0} // UTF-16LE + null
	if len(result) != len(expected) {
		t.Fatalf("encodeRegSZ(\"AB\"): expected %d bytes, got %d", len(expected), len(result))
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("encodeRegSZ(\"AB\"): byte %d: expected 0x%02x, got 0x%02x", i, expected[i], result[i])
		}
	}
}

func TestEncodeRegSZ_Empty(t *testing.T) {
	result := encodeRegSZ("")
	if len(result) != 2 { // just null terminator
		t.Errorf("encodeRegSZ(\"\"): expected 2 bytes (null terminator), got %d", len(result))
	}
}

func TestDecodeRegSZ_Simple(t *testing.T) {
	data := []byte{'H', 0, 'i', 0, 0, 0}
	result := decodeRegSZ(data)
	if result != "Hi" {
		t.Errorf("decodeRegSZ: expected \"Hi\", got %q", result)
	}
}

func TestDecodeRegSZ_Empty(t *testing.T) {
	result := decodeRegSZ([]byte{})
	if result != "" {
		t.Errorf("decodeRegSZ([]): expected empty, got %q", result)
	}
}

func TestDecodeRegSZ_NullOnly(t *testing.T) {
	result := decodeRegSZ([]byte{0, 0})
	if result != "" {
		t.Errorf("decodeRegSZ(null): expected empty, got %q", result)
	}
}

func TestDecodeRegSZ_TooShort(t *testing.T) {
	result := decodeRegSZ([]byte{0x41})
	if result != "" {
		t.Errorf("decodeRegSZ(1 byte): expected empty, got %q", result)
	}
}

func TestEncodeDecodeRegSZ_Roundtrip(t *testing.T) {
	testStrings := []string{"Hello", "C:\\Windows\\System32\\svchost.exe", "", "test 123"}
	for _, s := range testStrings {
		encoded := encodeRegSZ(s)
		decoded := decodeRegSZ(encoded)
		if decoded != s {
			t.Errorf("Roundtrip failed for %q: got %q", s, decoded)
		}
	}
}
