//go:build darwin

package commands

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredmanDarwinName(t *testing.T) {
	assertCommandName(t, &CredmanCommand{}, "credman")
}

func TestCredmanDarwinDescription(t *testing.T) {
	assertCommandHasDescription(t, &CredmanCommand{})
}

func TestCredmanDarwinUnknownAction(t *testing.T) {
	cmd := &CredmanCommand{}
	params, _ := json.Marshal(credmanArgs{Action: "vault"})
	result := cmd.Execute(mockTask("credman", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestCredmanDarwinDefaultActionIsList(t *testing.T) {
	cmd := &CredmanCommand{}
	result := cmd.Execute(mockTask("credman", ""))
	assertSuccess(t, result)
	assertOutputContains(t, result, "macOS Credential Stores")
}

func TestParseKeychainDumpGenp(t *testing.T) {
	dump := `keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="TestService"
    0x00000008 <blob>=<NULL>
    "acct"<blob>="testuser"
    "cdat"<timedate>=0x32303236303130313030303030305A00  "20260101000000Z"
    "crtr"<uint32>=<NULL>
    "cusi"<sint32>=<NULL>
    "desc"<blob>="application password"
    "gena"<blob>=<NULL>
    "icmt"<blob>=<NULL>
    "invi"<sint32>=<NULL>
    "mdat"<timedate>=0x32303236303130313030303030305A00  "20260101000000Z"
    "nega"<sint32>=<NULL>
    "prot"<blob>=<NULL>
    "scrp"<sint32>=<NULL>
    "svce"<blob>="com.example.app"
    "type"<uint32>=<NULL>
`
	entries := parseKeychainDump(dump, false)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Source != "Generic Password" {
		t.Errorf("Source = %q, want Generic Password", e.Source)
	}
	if e.Label != "TestService" {
		t.Errorf("Label = %q, want TestService", e.Label)
	}
	if e.Account != "testuser" {
		t.Errorf("Account = %q, want testuser", e.Account)
	}
	if e.Service != "com.example.app" {
		t.Errorf("Service = %q, want com.example.app", e.Service)
	}
	if e.Attrs["Description"] != "application password" {
		t.Errorf("Description = %q, want application password", e.Attrs["Description"])
	}
}

func TestParseKeychainDumpInet(t *testing.T) {
	dump := `keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: "inet"
attributes:
    0x00000007 <blob>="github.com"
    "acct"<blob>="admin@github.com"
    "cdat"<timedate>=0x32303236303130313030303030305A00  "20260101000000Z"
    "desc"<blob>=<NULL>
    "ptcl"<uint32>="htps"
    "port"<uint32>=0x00000000
    "srvr"<blob>="github.com"
    "svce"<blob>=<NULL>
`
	entries := parseKeychainDump(dump, false)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Source != "Internet Password" {
		t.Errorf("Source = %q, want Internet Password", e.Source)
	}
	if e.Service != "github.com" {
		t.Errorf("Service = %q, want github.com", e.Service)
	}
	if e.Attrs["Protocol"] != "htps" {
		t.Errorf("Protocol = %q, want htps", e.Attrs["Protocol"])
	}
}

func TestParseKeychainDumpWithData(t *testing.T) {
	dump := `keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="WiFi-Home"
    "acct"<blob>="WiFi-Home"
    "svce"<blob>="AirPort"
data:
"mysecretpassword"
`
	entries := parseKeychainDump(dump, true)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Secret != "mysecretpassword" {
		t.Errorf("Secret = %q, want mysecretpassword", entries[0].Secret)
	}
}

func TestParseKeychainDumpHexData(t *testing.T) {
	dump := `keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="TestApp"
    "acct"<blob>="user1"
    "svce"<blob>="com.test.app"
data:
0x70617373776F7264313233  "password123"
`
	entries := parseKeychainDump(dump, true)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Secret != "password123" {
		t.Errorf("Secret = %q, want password123", entries[0].Secret)
	}
}

func TestParseKeychainDumpSkipsBinaryData(t *testing.T) {
	dump := `keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="SystemKey"
    "acct"<blob>="system"
    "svce"<blob>="com.apple.system"
data:
0x0200000087191CA3  "\002\000\000\000\207\031\034\243"
`
	entries := parseKeychainDump(dump, true)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Secret != "" {
		t.Errorf("Expected empty secret for binary data, got %q", entries[0].Secret)
	}
}

func TestParseKeychainDumpSkipsNonPasswordClasses(t *testing.T) {
	dump := `keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: 0x0000000F
attributes:
    0x00000007 <blob>=<NULL>
keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="RealEntry"
    "acct"<blob>="user"
    "svce"<blob>="service"
`
	entries := parseKeychainDump(dump, false)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (skipping key class), got %d", len(entries))
	}
	if entries[0].Label != "RealEntry" {
		t.Errorf("Label = %q, want RealEntry", entries[0].Label)
	}
}

func TestParseKeychainDumpSkipsEmptyEntries(t *testing.T) {
	dump := `keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>=<NULL>
    "acct"<blob>=<NULL>
    "svce"<blob>=<NULL>
`
	entries := parseKeychainDump(dump, false)
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries for all-null item, got %d", len(entries))
	}
}

func TestParseKeychainDumpMultipleEntries(t *testing.T) {
	dump := `keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="App1"
    "acct"<blob>="user1"
    "svce"<blob>="com.app1"
keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="App2"
    "acct"<blob>="user2"
    "svce"<blob>="com.app2"
keychain: "/Library/Keychains/System.keychain"
version: 512
class: "inet"
attributes:
    0x00000007 <blob>="proxy.corp.com"
    "acct"<blob>="admin"
    "srvr"<blob>="proxy.corp.com"
    "ptcl"<uint32>="htps"
`
	entries := parseKeychainDump(dump, false)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Label != "App1" {
		t.Errorf("entries[0].Label = %q, want App1", entries[0].Label)
	}
	if entries[2].Source != "Internet Password" {
		t.Errorf("entries[2].Source = %q, want Internet Password", entries[2].Source)
	}
}

func TestFilterDarwinEntries(t *testing.T) {
	entries := []darwinCredEntry{
		{Label: "WiFi-Home", Account: "admin", Service: "AirPort"},
		{Label: "GitHub", Account: "dev@github.com", Service: "github.com"},
		{Label: "Slack", Account: "user@slack.com", Service: "slack.com"},
	}

	filtered := filterDarwinEntries(entries, "github")
	if len(filtered) != 1 {
		t.Fatalf("expected 1 match for 'github', got %d", len(filtered))
	}
	if filtered[0].Label != "GitHub" {
		t.Errorf("expected GitHub, got %s", filtered[0].Label)
	}

	filtered = filterDarwinEntries(entries, "*slack*")
	if len(filtered) != 1 {
		t.Fatalf("expected 1 match for '*slack*', got %d", len(filtered))
	}
}

func TestGroupDarwinBySource(t *testing.T) {
	entries := []darwinCredEntry{
		{Source: "Generic Password", Label: "B"},
		{Source: "Generic Password", Label: "A"},
		{Source: "WiFi", Label: "Home"},
		{Source: "Internet Password", Label: "Z"},
	}
	grouped := groupDarwinBySource(entries)
	if len(grouped["Generic Password"]) != 2 {
		t.Errorf("expected 2 Generic Password, got %d", len(grouped["Generic Password"]))
	}
	if grouped["Generic Password"][0].Label != "A" {
		t.Error("expected sorted order A, B")
	}
	if len(grouped["WiFi"]) != 1 {
		t.Errorf("expected 1 WiFi, got %d", len(grouped["WiFi"]))
	}
}

func TestIsPrintableSecret(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"password123", true},
		{"my secret!", true},
		{"with\ttab", true},
		{"", false},
		{"\x00\x01\x02", false},
		{strings.Repeat("a", 1025), false},
	}
	for _, tt := range tests {
		if got := isPrintableSecret(tt.input); got != tt.want {
			t.Errorf("isPrintableSecret(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestExtractDataFieldQuoted(t *testing.T) {
	block := `class: "genp"
data:
"simplepassword"
`
	got := extractDataField(block)
	if got != "simplepassword" {
		t.Errorf("extractDataField = %q, want simplepassword", got)
	}
}

func TestExtractDataFieldHexWithReadable(t *testing.T) {
	block := `class: "genp"
data:
0x48656C6C6F  "Hello"
`
	got := extractDataField(block)
	if got != "Hello" {
		t.Errorf("extractDataField = %q, want Hello", got)
	}
}

func TestExtractDataFieldEmpty(t *testing.T) {
	block := `class: "genp"
attributes:
    "acct"<blob>="user"
`
	got := extractDataField(block)
	if got != "" {
		t.Errorf("extractDataField = %q, want empty", got)
	}
}

func TestExtractKeychainPath(t *testing.T) {
	block := `keychain: "/Users/test/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
`
	got := extractKeychainPath(block)
	if got != "/Users/test/Library/Keychains/login.keychain-db" {
		t.Errorf("extractKeychainPath = %q", got)
	}
}

func TestSplitKeychainBlocks(t *testing.T) {
	input := `keychain: "/path1"
class: "genp"
keychain: "/path2"
class: "inet"
`
	blocks := splitKeychainBlocks(input)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(blocks))
	}
	if !strings.Contains(blocks[0], "path1") {
		t.Error("block 0 should contain path1")
	}
	if !strings.Contains(blocks[1], "path2") {
		t.Error("block 1 should contain path2")
	}
}
