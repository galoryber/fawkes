package agentfunctions

import (
	"strings"
	"testing"
)

func TestFormatWMIOPSEC_RemoteHost(t *testing.T) {
	msg := formatWMIOPSEC("execute", "192.168.1.10")
	if !strings.Contains(msg, "Remote WMI") {
		t.Errorf("expected 'Remote WMI', got %q", msg)
	}
	if !strings.Contains(msg, "192.168.1.10") {
		t.Errorf("expected host in message, got %q", msg)
	}
}

func TestFormatWMIOPSEC_LocalEmpty(t *testing.T) {
	msg := formatWMIOPSEC("query", "")
	if !strings.Contains(msg, "Local WMI") {
		t.Errorf("expected 'Local WMI', got %q", msg)
	}
}

func TestFormatWMIOPSEC_LocalDot(t *testing.T) {
	msg := formatWMIOPSEC("os-info", ".")
	if !strings.Contains(msg, "Local WMI") {
		t.Errorf("expected 'Local WMI' for '.', got %q", msg)
	}
}

func TestFormatWMIOPSEC_LocalLocalhost(t *testing.T) {
	msg := formatWMIOPSEC("process-list", "localhost")
	if !strings.Contains(msg, "Local WMI") {
		t.Errorf("expected 'Local WMI' for 'localhost', got %q", msg)
	}
}

func TestExtractWMIHost_ValidOutput(t *testing.T) {
	input := "WMI Process Create on DC01: cmd.exe /c whoami > output.txt"
	host, ok := extractWMIHost(input)
	if !ok {
		t.Fatal("expected match")
	}
	if host != "DC01" {
		t.Errorf("expected DC01, got %q", host)
	}
}

func TestExtractWMIHost_IPAddress(t *testing.T) {
	input := "WMI Process Create on 192.168.1.10: notepad.exe"
	host, ok := extractWMIHost(input)
	if !ok {
		t.Fatal("expected match")
	}
	if host != "192.168.1.10" {
		t.Errorf("expected 192.168.1.10, got %q", host)
	}
}

func TestExtractWMIHost_NoMatch(t *testing.T) {
	_, ok := extractWMIHost("WMI query returned 5 results")
	if ok {
		t.Error("expected no match for non-process-create output")
	}
}

func TestExtractWMIHost_Empty(t *testing.T) {
	_, ok := extractWMIHost("")
	if ok {
		t.Error("expected no match for empty input")
	}
}
