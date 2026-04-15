package agentfunctions

import (
	"strings"
	"testing"
)

func TestFormatRemoteRegOPSEC_ReadAction(t *testing.T) {
	msg := formatRemoteRegOPSEC("read", "DC01")
	if !strings.Contains(msg, "DC01") {
		t.Errorf("expected server in message")
	}
	if strings.Contains(msg, "Write/delete") {
		t.Errorf("read action should not warn about write/delete")
	}
}

func TestFormatRemoteRegOPSEC_SetAction(t *testing.T) {
	msg := formatRemoteRegOPSEC("set", "SRV01")
	if !strings.Contains(msg, "Write/delete") {
		t.Errorf("set action should warn about write/delete")
	}
}

func TestFormatRemoteRegOPSEC_DeleteAction(t *testing.T) {
	msg := formatRemoteRegOPSEC("delete", "SRV01")
	if !strings.Contains(msg, "Write/delete") {
		t.Errorf("delete action should warn about write/delete")
	}
}

func TestFormatRemoteRegOPSEC_PipeTransport(t *testing.T) {
	msg := formatRemoteRegOPSEC("query", "any")
	if !strings.Contains(msg, "winreg") {
		t.Errorf("expected winreg pipe reference")
	}
}

func TestFormatRemoteRegOPSEC_EnumAction(t *testing.T) {
	msg := formatRemoteRegOPSEC("enum", "DC01")
	if strings.Contains(msg, "Write/delete") {
		t.Errorf("enum action should not warn about write/delete")
	}
}
