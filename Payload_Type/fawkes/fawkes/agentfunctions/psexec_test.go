package agentfunctions

import (
	"testing"
)

func TestExtractPsExecInfo_BothFields(t *testing.T) {
	input := "PSExec on DC01: cmd.exe /c whoami\nService: fawkes_abc123"
	host, service := extractPsExecInfo(input)
	if host != "DC01" {
		t.Errorf("expected DC01, got %q", host)
	}
	if service != "fawkes_abc123" {
		t.Errorf("expected fawkes_abc123, got %q", service)
	}
}

func TestExtractPsExecInfo_HostOnly(t *testing.T) {
	input := "PSExec on 192.168.1.10: executing"
	host, service := extractPsExecInfo(input)
	if host != "192.168.1.10" {
		t.Errorf("expected 192.168.1.10, got %q", host)
	}
	if service != "unknown" {
		t.Errorf("expected unknown (no service line), got %q", service)
	}
}

func TestExtractPsExecInfo_ServiceOnly(t *testing.T) {
	input := "Remote execution\nService: my_svc"
	host, service := extractPsExecInfo(input)
	if host != "unknown" {
		t.Errorf("expected unknown (no host line), got %q", host)
	}
	if service != "my_svc" {
		t.Errorf("expected my_svc, got %q", service)
	}
}

func TestExtractPsExecInfo_NoMatch(t *testing.T) {
	host, service := extractPsExecInfo("Some random output")
	if host != "unknown" || service != "unknown" {
		t.Errorf("expected unknown/unknown, got %q/%q", host, service)
	}
}

func TestExtractPsExecInfo_Empty(t *testing.T) {
	host, service := extractPsExecInfo("")
	if host != "unknown" || service != "unknown" {
		t.Errorf("expected unknown/unknown, got %q/%q", host, service)
	}
}
