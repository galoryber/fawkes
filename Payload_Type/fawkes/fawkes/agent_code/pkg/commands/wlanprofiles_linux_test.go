//go:build linux

package commands

import (
	"testing"
)

// --- parseNMProfile tests ---

func TestParseNMProfile_WPA(t *testing.T) {
	content := `[connection]
id=MyNetwork
uuid=12345678-1234-1234-1234-123456789abc
type=wifi

[wifi]
mode=infrastructure
ssid=MyNetwork

[wifi-security]
key-mgmt=wpa-psk
psk=supersecretpassword

[ipv4]
method=auto
`
	profile := parseNMProfile(content, "/etc/NetworkManager/system-connections/MyNetwork.nmconnection")

	if profile.SSID != "MyNetwork" {
		t.Errorf("expected SSID 'MyNetwork', got %q", profile.SSID)
	}
	if profile.AuthType != "WPA-PSK" {
		t.Errorf("expected AuthType 'WPA-PSK', got %q", profile.AuthType)
	}
	if profile.Key != "supersecretpassword" {
		t.Errorf("expected Key 'supersecretpassword', got %q", profile.Key)
	}
	if profile.Source != "/etc/NetworkManager/system-connections/MyNetwork.nmconnection" {
		t.Errorf("unexpected Source: %q", profile.Source)
	}
}

func TestParseNMProfile_OpenNetwork(t *testing.T) {
	content := `[connection]
id=CoffeeShop
type=wifi

[wifi]
ssid=CoffeeShop

[ipv4]
method=auto
`
	profile := parseNMProfile(content, "/path/to/file")

	if profile.SSID != "CoffeeShop" {
		t.Errorf("expected SSID 'CoffeeShop', got %q", profile.SSID)
	}
	if profile.AuthType != "" {
		t.Errorf("expected empty AuthType for open network, got %q", profile.AuthType)
	}
	if profile.Key != "" {
		t.Errorf("expected empty Key for open network, got %q", profile.Key)
	}
}

func TestParseNMProfile_NoWifiSection(t *testing.T) {
	content := `[connection]
id=VPN
type=vpn

[vpn]
service-type=org.freedesktop.NetworkManager.openvpn
`
	profile := parseNMProfile(content, "/path/to/file")

	if profile.SSID != "" {
		t.Errorf("expected empty SSID for non-wifi connection, got %q", profile.SSID)
	}
}

func TestParseNMProfile_WPAEnterprise(t *testing.T) {
	content := `[wifi]
ssid=CorpNet

[wifi-security]
key-mgmt=wpa-eap
`
	profile := parseNMProfile(content, "/path")

	if profile.SSID != "CorpNet" {
		t.Errorf("expected SSID 'CorpNet', got %q", profile.SSID)
	}
	if profile.AuthType != "WPA-EAP" {
		t.Errorf("expected AuthType 'WPA-EAP', got %q", profile.AuthType)
	}
}

func TestParseNMProfile_SectionSwitch(t *testing.T) {
	// Verify parser properly tracks section boundaries
	content := `[wifi]
ssid=TestNet

[wifi-security]
key-mgmt=wpa-psk
psk=pass123

[ipv4]
method=auto
ssid=should_not_be_captured
`
	profile := parseNMProfile(content, "/path")

	if profile.SSID != "TestNet" {
		t.Errorf("expected SSID 'TestNet', got %q", profile.SSID)
	}
	if profile.Key != "pass123" {
		t.Errorf("expected Key 'pass123', got %q", profile.Key)
	}
}

func TestParseNMProfile_Empty(t *testing.T) {
	profile := parseNMProfile("", "/path")
	if profile.SSID != "" {
		t.Errorf("expected empty SSID, got %q", profile.SSID)
	}
}

// --- parseWPASupplicant tests ---

func TestParseWPASupplicant_SingleNetwork(t *testing.T) {
	content := `ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=US

network={
	ssid="HomeNetwork"
	psk="mypassword123"
	key_mgmt=WPA-PSK
}
`
	profiles := parseWPASupplicant(content, "/etc/wpa_supplicant/wpa_supplicant.conf")

	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	if profiles[0].SSID != "HomeNetwork" {
		t.Errorf("expected SSID 'HomeNetwork', got %q", profiles[0].SSID)
	}
	if profiles[0].Key != "mypassword123" {
		t.Errorf("expected Key 'mypassword123', got %q", profiles[0].Key)
	}
	if profiles[0].AuthType != "WPA-PSK" {
		t.Errorf("expected AuthType 'WPA-PSK', got %q", profiles[0].AuthType)
	}
	if profiles[0].Source != "/etc/wpa_supplicant/wpa_supplicant.conf" {
		t.Errorf("unexpected Source: %q", profiles[0].Source)
	}
}

func TestParseWPASupplicant_MultipleNetworks(t *testing.T) {
	content := `ctrl_interface=/var/run/wpa_supplicant

network={
	ssid="Network1"
	psk="pass1"
}

network={
	ssid="Network2"
	psk="pass2"
	key_mgmt=WPA-PSK
}

network={
	ssid="OpenNet"
	key_mgmt=NONE
}
`
	profiles := parseWPASupplicant(content, "/path")

	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d", len(profiles))
	}
	if profiles[0].SSID != "Network1" {
		t.Errorf("profile 0: expected 'Network1', got %q", profiles[0].SSID)
	}
	if profiles[1].SSID != "Network2" {
		t.Errorf("profile 1: expected 'Network2', got %q", profiles[1].SSID)
	}
	if profiles[2].SSID != "OpenNet" {
		t.Errorf("profile 2: expected 'OpenNet', got %q", profiles[2].SSID)
	}
	if profiles[2].AuthType != "NONE" {
		t.Errorf("profile 2: expected AuthType 'NONE', got %q", profiles[2].AuthType)
	}
}

func TestParseWPASupplicant_DefaultKeyMgmt(t *testing.T) {
	content := `network={
	ssid="NoKeyMgmt"
	psk="password"
}
`
	profiles := parseWPASupplicant(content, "/path")

	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	// Should default to WPA-PSK when key_mgmt not specified
	if profiles[0].AuthType != "WPA-PSK" {
		t.Errorf("expected default AuthType 'WPA-PSK', got %q", profiles[0].AuthType)
	}
}

func TestParseWPASupplicant_EmptySSID(t *testing.T) {
	content := `network={
	psk="password"
}
`
	profiles := parseWPASupplicant(content, "/path")

	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles (no SSID), got %d", len(profiles))
	}
}

func TestParseWPASupplicant_EmptyContent(t *testing.T) {
	profiles := parseWPASupplicant("", "/path")
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles, got %d", len(profiles))
	}
}

func TestParseWPASupplicant_NoNetworkBlocks(t *testing.T) {
	content := `ctrl_interface=DIR=/var/run/wpa_supplicant
update_config=1
`
	profiles := parseWPASupplicant(content, "/path")
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles, got %d", len(profiles))
	}
}

func TestParseWPASupplicant_PSKWithoutQuotes(t *testing.T) {
	// PSK can be a raw hex string (64 hex chars) without quotes
	content := `network={
	ssid="HexPSK"
	psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
}
`
	profiles := parseWPASupplicant(content, "/path")

	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	if profiles[0].Key != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("expected hex PSK, got %q", profiles[0].Key)
	}
}
