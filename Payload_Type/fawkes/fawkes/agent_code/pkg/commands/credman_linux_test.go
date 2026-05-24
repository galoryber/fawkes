//go:build linux

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSecretToolOutput(t *testing.T) {
	input := `[/org/freedesktop/secrets/collection/login/1]
label = Chrome Safe Storage
secret =
created = 2024-01-15 10:30:00
modified = 2024-06-01 08:00:00
schema = chrome_libsecret_os_crypt_password_v2
attribute.application = chrome
attribute.xdg:schema = chrome_libsecret_os_crypt_password_v2

[/org/freedesktop/secrets/collection/login/2]
label = WiFi Password
secret =
created = 2024-02-20 14:00:00
modified = 2024-02-20 14:00:00
schema = org.freedesktop.NetworkManager.Connection
attribute.username = admin
attribute.server = myrouter.local
`
	entries := parseSecretToolOutput(input, "Secret Service")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].Label != "Chrome Safe Storage" {
		t.Errorf("entry 0 label: got %q, want %q", entries[0].Label, "Chrome Safe Storage")
	}
	if entries[0].Source != "Secret Service" {
		t.Errorf("entry 0 source: got %q", entries[0].Source)
	}
	if entries[0].Attrs["application"] != "chrome" {
		t.Errorf("entry 0 application attr: got %q", entries[0].Attrs["application"])
	}

	if entries[1].Label != "WiFi Password" {
		t.Errorf("entry 1 label: got %q", entries[1].Label)
	}
	if entries[1].Account != "admin" {
		t.Errorf("entry 1 account: got %q, want %q", entries[1].Account, "admin")
	}
	if entries[1].Attrs["server"] != "myrouter.local" {
		t.Errorf("entry 1 server attr: got %q", entries[1].Attrs["server"])
	}
}

func TestParseSecretToolOutputEmpty(t *testing.T) {
	entries := parseSecretToolOutput("", "Secret Service")
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries for empty input, got %d", len(entries))
	}
}

func TestParseSecretToolOutputNoLabel(t *testing.T) {
	input := `[/org/freedesktop/secrets/collection/login/1]
secret = mysecret
attribute.user = testuser
`
	entries := parseSecretToolOutput(input, "Secret Service")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Label != "" {
		t.Errorf("expected empty label, got %q", entries[0].Label)
	}
	if entries[0].Account != "testuser" {
		t.Errorf("expected account 'testuser', got %q", entries[0].Account)
	}
	if entries[0].Secret != "mysecret" {
		t.Errorf("expected secret 'mysecret', got %q", entries[0].Secret)
	}
}

func TestParseNMConnectionFile(t *testing.T) {
	content := `[connection]
id=MyWiFi
type=wifi

[wifi]
ssid=MyWiFi

[wifi-security]
key-mgmt=wpa-psk
psk=supersecretpassword

[ipv4]
method=auto
`
	dir := t.TempDir()
	path := filepath.Join(dir, "MyWiFi.nmconnection")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	entry, err := parseNMConnectionFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Label != "MyWiFi" {
		t.Errorf("label: got %q, want %q", entry.Label, "MyWiFi")
	}
	if entry.Secret != "supersecretpassword" {
		t.Errorf("secret: got %q, want %q", entry.Secret, "supersecretpassword")
	}
	if entry.Attrs["security"] != "wpa-psk" {
		t.Errorf("security attr: got %q", entry.Attrs["security"])
	}
}

func TestParseNMConnectionFileVPN(t *testing.T) {
	content := `[connection]
id=Work VPN
type=vpn

[vpn]
username=john.doe
password=vpnpass123
gateway=vpn.company.com

[ipv4]
method=auto
`
	dir := t.TempDir()
	path := filepath.Join(dir, "work-vpn.nmconnection")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	entry, err := parseNMConnectionFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Label != "Work VPN" {
		t.Errorf("label: got %q, want %q", entry.Label, "Work VPN")
	}
	if entry.Account != "john.doe" {
		t.Errorf("account: got %q, want %q", entry.Account, "john.doe")
	}
	if entry.Secret != "vpnpass123" {
		t.Errorf("secret: got %q, want %q", entry.Secret, "vpnpass123")
	}
}

func TestParseNMConnectionFile8021x(t *testing.T) {
	content := `[connection]
id=CorpNet
type=wifi

[wifi]
ssid=CorpNet

[802-1x]
identity=employee@corp.com
password=enterprisepass
`
	dir := t.TempDir()
	path := filepath.Join(dir, "corpnet.nmconnection")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	entry, err := parseNMConnectionFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Account != "employee@corp.com" {
		t.Errorf("account: got %q", entry.Account)
	}
	if entry.Secret != "enterprisepass" {
		t.Errorf("secret: got %q", entry.Secret)
	}
}

func TestEnumerateGNOMEOnlineAccountsNoFile(t *testing.T) {
	// When GOA config doesn't exist, should return empty
	entries := enumerateGNOMEOnlineAccounts()
	// Result depends on test environment — just verify no panic
	_ = entries
}

func TestFilterCredEntries(t *testing.T) {
	entries := []linuxCredEntry{
		{Label: "Chrome Safe Storage", Account: "chrome"},
		{Label: "WiFi MySSID", Account: "admin"},
		{Label: "VPN Office", Account: "john.doe"},
	}

	tests := []struct {
		filter string
		want   int
	}{
		{"chrome", 1},
		{"WiFi", 1},
		{"john", 1},
		{"*office*", 1},
		{"nonexistent", 0},
		{"", 3}, // empty filter matches all (but filtered upstream)
	}

	for _, tt := range tests {
		got := filterCredEntries(entries, tt.filter)
		if len(got) != tt.want {
			t.Errorf("filter %q: got %d entries, want %d", tt.filter, len(got), tt.want)
		}
	}
}

func TestGroupBySource(t *testing.T) {
	entries := []linuxCredEntry{
		{Source: "Secret Service", Label: "B"},
		{Source: "Secret Service", Label: "A"},
		{Source: "NetworkManager", Label: "WiFi"},
		{Source: "KWallet", Label: "Entry1"},
	}

	grouped := groupBySource(entries)
	if len(grouped["Secret Service"]) != 2 {
		t.Errorf("Secret Service count: got %d, want 2", len(grouped["Secret Service"]))
	}
	if len(grouped["NetworkManager"]) != 1 {
		t.Errorf("NetworkManager count: got %d, want 1", len(grouped["NetworkManager"]))
	}
	if len(grouped["KWallet"]) != 1 {
		t.Errorf("KWallet count: got %d, want 1", len(grouped["KWallet"]))
	}

	// Verify sorting within group
	if grouped["Secret Service"][0].Label != "A" {
		t.Errorf("Secret Service should be sorted: first=%q, want 'A'", grouped["Secret Service"][0].Label)
	}
}

func TestCredmanLinuxListAction(t *testing.T) {
	// Test the list action — will work in any environment (may find 0 creds)
	result := credmanLinuxList(credmanArgs{Action: "list"}, false)
	if result.Status != "success" {
		t.Errorf("expected success status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "=== Linux Credential Stores") {
		t.Errorf("output should contain header, got: %s", result.Output[:min(100, len(result.Output))])
	}
}

func TestCredmanLinuxDumpAction(t *testing.T) {
	result := credmanLinuxList(credmanArgs{Action: "dump"}, true)
	if result.Status != "success" {
		t.Errorf("expected success status, got %q", result.Status)
	}
}

func TestEnumerateNetworkManagerNoDir(t *testing.T) {
	// On most CI/test environments, NM connections dir won't be readable
	entries, errMsg := enumerateNetworkManager()
	// Should not panic, and should return a meaningful error or empty list
	_ = entries
	_ = errMsg
}

func TestSecretToolAttrRegex(t *testing.T) {
	tests := []struct {
		line string
		key  string
		val  string
	}{
		{"attribute.application = chrome", "application", "chrome"},
		{"attribute.xdg:schema = org.freedesktop.Secret.Generic", "xdg:schema", "org.freedesktop.Secret.Generic"},
		{"attribute.username = admin", "username", "admin"},
	}

	for _, tt := range tests {
		m := secretToolAttrRe.FindStringSubmatch(tt.line)
		if m == nil {
			t.Errorf("regex didn't match: %q", tt.line)
			continue
		}
		if m[1] != tt.key {
			t.Errorf("key: got %q, want %q", m[1], tt.key)
		}
		if m[2] != tt.val {
			t.Errorf("val: got %q, want %q", m[2], tt.val)
		}
	}
}

