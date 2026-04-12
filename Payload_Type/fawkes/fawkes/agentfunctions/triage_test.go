package agentfunctions

import (
	"sort"
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
	// Port 22 — different from default 445
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
	// Lines with only one field should be skipped
	input := `onlyhost
192.168.100.51       445      microsoft-ds`

	hosts := parsePortScanForPort(input, 445)
	if len(hosts) != 1 {
		t.Errorf("expected 1 host (single-field line skipped), got %d: %v", len(hosts), hosts)
	}
}
