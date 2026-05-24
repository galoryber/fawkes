package agentfunctions

import (
	"sort"
	"testing"
)

// --- parsePortScanHosts Tests ---

func TestParsePortScanHosts_Standard(t *testing.T) {
	input := `Host                 Port     Service
--------------------------------------------------
192.168.100.51       445      microsoft-ds
192.168.100.53       445      microsoft-ds
192.168.100.54       80       http

Scanned 4 hosts, Found 3 alive`

	hosts := parsePortScanHosts(input)
	sort.Strings(hosts)

	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d: %v", len(hosts), hosts)
	}
	expected := []string{"192.168.100.51", "192.168.100.53", "192.168.100.54"}
	for i, h := range expected {
		if hosts[i] != h {
			t.Errorf("host[%d] = %q, want %q", i, hosts[i], h)
		}
	}
}

func TestParsePortScanHosts_Empty(t *testing.T) {
	hosts := parsePortScanHosts("")
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts for empty input, got %d", len(hosts))
	}
}

func TestParsePortScanHosts_NoIPAddresses(t *testing.T) {
	input := `Host                 Port     Service
--------------------------------------------------
Scanned 0 hosts, Found 0 alive`

	hosts := parsePortScanHosts(input)
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d: %v", len(hosts), hosts)
	}
}

func TestParsePortScanHosts_DeduplicatesHosts(t *testing.T) {
	input := `10.0.0.1       445      microsoft-ds
10.0.0.1       80       http
10.0.0.1       22       ssh`

	hosts := parsePortScanHosts(input)
	if len(hosts) != 1 {
		t.Errorf("expected 1 unique host, got %d: %v", len(hosts), hosts)
	}
}

func TestParsePortScanHosts_MultipleSubnets(t *testing.T) {
	input := `10.0.0.1       445      microsoft-ds
172.16.0.100   22       ssh
192.168.1.1    80       http`

	hosts := parsePortScanHosts(input)
	if len(hosts) != 3 {
		t.Errorf("expected 3 hosts from different subnets, got %d: %v", len(hosts), hosts)
	}
}

func TestParsePortScanHosts_NonIPLines(t *testing.T) {
	// Lines that don't start with IP addresses should be skipped
	input := `hostname       445      microsoft-ds
192.168.100.51 445      microsoft-ds
Header line
---dashes---`

	hosts := parsePortScanHosts(input)
	if len(hosts) != 1 {
		t.Errorf("expected 1 host (non-IP lines skipped), got %d: %v", len(hosts), hosts)
	}
}

func TestParsePortScanHosts_LeadingWhitespace(t *testing.T) {
	input := `  192.168.100.51       445      microsoft-ds
    192.168.100.52     22       ssh`

	hosts := parsePortScanHosts(input)
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts with leading whitespace, got %d: %v", len(hosts), hosts)
	}
}
