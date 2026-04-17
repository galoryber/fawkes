package agentfunctions

import (
	"strings"
	"testing"
)

func TestWdigestOPSECMessage_Enable(t *testing.T) {
	msg := wdigestOPSECMessage("enable")
	if !strings.Contains(msg, "UseLogonCredential=1") {
		t.Errorf("enable message should mention UseLogonCredential=1, got %q", msg)
	}
	if !strings.Contains(msg, "OPSEC WARNING") {
		t.Errorf("expected OPSEC WARNING prefix, got %q", msg)
	}
}

func TestWdigestOPSECMessage_Disable(t *testing.T) {
	msg := wdigestOPSECMessage("disable")
	if !strings.Contains(msg, "UseLogonCredential=0") {
		t.Errorf("disable message should mention UseLogonCredential=0, got %q", msg)
	}
	if !strings.Contains(msg, "Registry") {
		t.Errorf("disable message should mention Registry, got %q", msg)
	}
}

func TestWdigestOPSECMessage_Status(t *testing.T) {
	msg := wdigestOPSECMessage("status")
	if !strings.Contains(msg, "Low risk") {
		t.Errorf("status message should indicate low risk, got %q", msg)
	}
}

func TestWdigestOPSECMessage_Unknown(t *testing.T) {
	msg := wdigestOPSECMessage("unknown-action")
	if !strings.Contains(msg, "Low risk") {
		t.Errorf("unknown action should fall through to default (low risk status), got %q", msg)
	}
}

func TestWdigestStatusEnabled_True(t *testing.T) {
	if !wdigestStatusEnabled("WDigest UseLogonCredential: ENABLED") {
		t.Error("expected true for ENABLED output")
	}
}

func TestWdigestStatusEnabled_Disabled(t *testing.T) {
	if wdigestStatusEnabled("WDigest UseLogonCredential: DISABLED (default)") {
		t.Error("expected false for DISABLED output")
	}
}

func TestWdigestStatusEnabled_Empty(t *testing.T) {
	if wdigestStatusEnabled("") {
		t.Error("expected false for empty input")
	}
}
