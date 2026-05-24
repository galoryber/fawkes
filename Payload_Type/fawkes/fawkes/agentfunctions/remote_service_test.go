package agentfunctions

import (
	"strings"
	"testing"
)

func TestFormatRemoteServiceOPSEC_Create(t *testing.T) {
	msg := formatRemoteServiceOPSEC("create", "DC01")
	if !strings.Contains(msg, "Event ID 7045") {
		t.Errorf("expected Event ID 7045 for create, got %q", msg)
	}
	if !strings.Contains(msg, "DC01") {
		t.Errorf("expected server name in message")
	}
}

func TestFormatRemoteServiceOPSEC_Delete(t *testing.T) {
	msg := formatRemoteServiceOPSEC("delete", "10.0.0.1")
	if !strings.Contains(msg, "defense evasion") {
		t.Errorf("expected defense evasion warning for delete")
	}
}

func TestFormatRemoteServiceOPSEC_ModifyPath(t *testing.T) {
	msg := formatRemoteServiceOPSEC("modify-path", "SRV01")
	if !strings.Contains(msg, "CRITICAL") {
		t.Errorf("expected CRITICAL for modify-path")
	}
	if !strings.Contains(msg, "Event ID 7040") {
		t.Errorf("expected Event ID 7040 for modify-path")
	}
}

func TestFormatRemoteServiceOPSEC_DLLSideload(t *testing.T) {
	msg := formatRemoteServiceOPSEC("dll-sideload", "SRV01")
	if !strings.Contains(msg, "CRITICAL") {
		t.Errorf("expected CRITICAL for dll-sideload")
	}
	if !strings.Contains(msg, "ServiceDll") {
		t.Errorf("expected ServiceDll reference for dll-sideload")
	}
}

func TestFormatRemoteServiceOPSEC_List(t *testing.T) {
	msg := formatRemoteServiceOPSEC("list", "DC01")
	if !strings.Contains(msg, "enumeration") {
		t.Errorf("expected enumeration for list action")
	}
}

func TestFormatRemoteServiceOPSEC_StartStop(t *testing.T) {
	msg := formatRemoteServiceOPSEC("start", "DC01")
	if !strings.Contains(msg, "Event ID 7036") {
		t.Errorf("expected Event ID 7036 for start")
	}
}

func TestFormatRemoteServiceOPSEC_PipeTransport(t *testing.T) {
	msg := formatRemoteServiceOPSEC("create", "any")
	if !strings.Contains(msg, "svcctl") {
		t.Errorf("expected svcctl pipe reference")
	}
}
