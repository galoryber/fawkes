package agentfunctions

import (
	"strings"
	"testing"
)

func TestDpapiOPSECMessage_Decrypt(t *testing.T) {
	msg := dpapiOPSECMessage("decrypt")
	if !strings.Contains(msg, "decrypt") {
		t.Errorf("expected action 'decrypt' in message, got %q", msg)
	}
	if !strings.Contains(msg, "CryptUnprotectData") {
		t.Errorf("expected CryptUnprotectData mention for decrypt action, got %q", msg)
	}
	if !strings.Contains(msg, "OPSEC WARNING") {
		t.Errorf("expected OPSEC WARNING prefix, got %q", msg)
	}
}

func TestDpapiOPSECMessage_Masterkeys(t *testing.T) {
	msg := dpapiOPSECMessage("masterkeys")
	if !strings.Contains(msg, "master key") {
		t.Errorf("expected 'master key' in masterkeys message, got %q", msg)
	}
	if !strings.Contains(msg, "Protect") {
		t.Errorf("expected APPDATA Protect path mention, got %q", msg)
	}
}

func TestDpapiOPSECMessage_Wifi(t *testing.T) {
	msg := dpapiOPSECMessage("wifi")
	if !strings.Contains(msg, "Wi-Fi") {
		t.Errorf("expected 'Wi-Fi' in wifi message, got %q", msg)
	}
	if !strings.Contains(msg, "T1555.005") {
		t.Errorf("expected T1555.005 MITRE mapping in wifi message, got %q", msg)
	}
}

func TestDpapiOPSECMessage_Browser(t *testing.T) {
	msg := dpapiOPSECMessage("browser")
	if !strings.Contains(msg, "Chrome") {
		t.Errorf("expected Chrome mention in browser message, got %q", msg)
	}
	if !strings.Contains(msg, "T1555.003") {
		t.Errorf("expected T1555.003 MITRE mapping in browser message, got %q", msg)
	}
}

func TestDpapiOPSECMessage_ChromeKey(t *testing.T) {
	msg := dpapiOPSECMessage("chrome-key")
	// chrome-key falls to default
	if !strings.Contains(msg, "OPSEC WARNING") {
		t.Errorf("expected OPSEC WARNING prefix, got %q", msg)
	}
	if !strings.Contains(msg, "chrome-key") {
		t.Errorf("expected action 'chrome-key' in message, got %q", msg)
	}
}

func TestDpapiOPSECMessage_Unknown(t *testing.T) {
	msg := dpapiOPSECMessage("unknown")
	if !strings.Contains(msg, "protected data") {
		t.Errorf("expected default message for unknown action, got %q", msg)
	}
}
