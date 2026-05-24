package agentfunctions

import (
	"sort"
	"strings"
	"testing"
)

// --- parsePortScanForPort Tests ---

func TestParsePortScanForPort_Standard(t *testing.T) {
	input := `Host                 Port     Service
--------------------------------------------------
192.168.100.51       445      microsoft-ds
192.168.100.53       445      microsoft-ds
192.168.100.52       80       http
192.168.100.54       445      microsoft-ds

Scanned 4 hosts, Found 4 alive`

	hosts := parsePortScanForPort(input, 445)
	sort.Strings(hosts)

	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts with port 445, got %d: %v", len(hosts), hosts)
	}
	expected := []string{"192.168.100.51", "192.168.100.53", "192.168.100.54"}
	for i, h := range expected {
		if hosts[i] != h {
			t.Errorf("host[%d] = %q, want %q", i, hosts[i], h)
		}
	}
}

func TestParsePortScanForPort_NoMatches(t *testing.T) {
	input := `Host                 Port     Service
--------------------------------------------------
192.168.100.51       80       http
192.168.100.52       443      https`

	hosts := parsePortScanForPort(input, 445)
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts for port 445, got %d: %v", len(hosts), hosts)
	}
}

func TestParsePortScanForPort_EmptyInput(t *testing.T) {
	hosts := parsePortScanForPort("", 445)
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts for empty input, got %d", len(hosts))
	}
}

func TestParsePortScanForPort_DeduplicatesHosts(t *testing.T) {
	input := `192.168.100.51       445      microsoft-ds
192.168.100.51       445      microsoft-ds
192.168.100.51       445      microsoft-ds`

	hosts := parsePortScanForPort(input, 445)
	if len(hosts) != 1 {
		t.Errorf("expected 1 unique host, got %d: %v", len(hosts), hosts)
	}
}

func TestParsePortScanForPort_SkipsHeaders(t *testing.T) {
	input := `Host                 Port     Service
--------------------------------------------------
Found 2 alive hosts
Scanned 5 hosts`

	hosts := parsePortScanForPort(input, 445)
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts (all header lines), got %d: %v", len(hosts), hosts)
	}
}

func TestParsePortScanForPort_InvalidHostFormat(t *testing.T) {
	input := `noip 445 microsoft-ds
192.168.100.51       445      microsoft-ds`

	hosts := parsePortScanForPort(input, 445)
	// "noip" doesn't contain "." or ":" so should be filtered
	if len(hosts) != 1 {
		t.Errorf("expected 1 valid host, got %d: %v", len(hosts), hosts)
	}
	if len(hosts) > 0 && hosts[0] != "192.168.100.51" {
		t.Errorf("expected 192.168.100.51, got %q", hosts[0])
	}
}

func TestParsePortScanForPort_IPv6Host(t *testing.T) {
	input := `::1       445      microsoft-ds
fe80::1   22       ssh`

	hosts := parsePortScanForPort(input, 445)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "::1" {
		t.Errorf("expected ::1, got %q", hosts[0])
	}
}

func TestParsePortScanForPort_PortAsString(t *testing.T) {
	input := `192.168.100.51       22       ssh
192.168.100.52       22       ssh
192.168.100.53       80       http`

	hosts := parsePortScanForPort(input, 22)
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts with port 22, got %d: %v", len(hosts), hosts)
	}
}

func TestParsePortScanForPort_TrimWhitespace(t *testing.T) {
	input := `  192.168.100.51       445      microsoft-ds
  192.168.100.52       445      microsoft-ds  `

	hosts := parsePortScanForPort(input, 445)
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts with trimmed whitespace, got %d: %v", len(hosts), hosts)
	}
}

func TestParsePortScanForPort_SingleField(t *testing.T) {
	input := `onlyhost
192.168.100.51       445      microsoft-ds`

	hosts := parsePortScanForPort(input, 445)
	if len(hosts) != 1 {
		t.Errorf("expected 1 host (single-field line skipped), got %d: %v", len(hosts), hosts)
	}
}

// --- parseTriageResults Tests ---

func TestParseTriageResults_Valid(t *testing.T) {
	jsonData := `[
		{"path": "/home/user/doc.pdf", "category": "documents"},
		{"path": "/home/user/resume.docx", "category": "documents"},
		{"path": "/home/user/.ssh/id_rsa", "category": "credentials"},
		{"path": "/etc/shadow", "category": "credentials"},
		{"path": "/opt/app/config.yml", "category": "configs"}
	]`

	results := parseTriageResults(jsonData)
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}

	categories := map[string]int{}
	for _, r := range results {
		categories[r.Category]++
	}
	if categories["documents"] != 2 {
		t.Errorf("documents = %d, want 2", categories["documents"])
	}
	if categories["credentials"] != 2 {
		t.Errorf("credentials = %d, want 2", categories["credentials"])
	}
	if categories["configs"] != 1 {
		t.Errorf("configs = %d, want 1", categories["configs"])
	}
}

func TestParseTriageResults_EmptyInputs(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"empty array", "[]"},
		{"invalid json", "not-json"},
		{"wrong type", `{"key": "value"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := parseTriageResults(tt.input)
			if len(results) != 0 {
				t.Errorf("expected 0 results for %q, got %d", tt.input, len(results))
			}
		})
	}
}

// --- triageOPSECMessage Tests ---

func TestTriageOPSECMessage_ReconChain(t *testing.T) {
	msg := triageOPSECMessage("recon-chain", "192.168.1.0/24")
	if !strings.Contains(msg, "192.168.1.0/24") {
		t.Error("recon-chain OPSEC message should include target")
	}
	if !strings.Contains(msg, "Recon Chain") {
		t.Error("recon-chain OPSEC message should mention Recon Chain")
	}
	if !strings.Contains(msg, "port scan") {
		t.Error("recon-chain should mention port scan step")
	}
}

func TestTriageOPSECMessage_Regular(t *testing.T) {
	msg := triageOPSECMessage("all", "")
	if strings.Contains(msg, "Recon Chain") {
		t.Error("regular triage should not mention Recon Chain")
	}
	if !strings.Contains(msg, "triage") {
		t.Error("regular message should mention triage")
	}
}

// --- validateReconChainParams Tests ---

func TestValidateReconChainParams(t *testing.T) {
	// Empty target should fail
	err := validateReconChainParams("", "445")
	if err == "" {
		t.Error("expected error for empty target")
	}

	// Valid target
	err = validateReconChainParams("192.168.1.0/24", "445")
	if err != "" {
		t.Errorf("unexpected error: %s", err)
	}

	// Valid target, empty ports (should still succeed — ports are optional)
	err = validateReconChainParams("10.0.0.1-10", "")
	if err != "" {
		t.Errorf("unexpected error with empty ports: %s", err)
	}
}
