package commands

import (
	"testing"
)

func TestPortScanCommandName(t *testing.T) {
	cmd := &PortScanCommand{}
	if cmd.Name() != "port-scan" {
		t.Errorf("expected 'port-scan', got %q", cmd.Name())
	}
}

func TestParseHostsSingleIP(t *testing.T) {
	hosts, err := parseHosts("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "192.168.1.1" {
		t.Errorf("expected [192.168.1.1], got %v", hosts)
	}
}

func TestParseHostsMultiple(t *testing.T) {
	hosts, err := parseHosts("10.0.0.1,10.0.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}
}

func TestParseHostsCIDR(t *testing.T) {
	hosts, err := parseHosts("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 = 4 IPs, minus network and broadcast = 2 usable
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts from /30, got %d: %v", len(hosts), hosts)
	}
}

func TestParseHostsRange(t *testing.T) {
	hosts, err := parseHosts("10.0.0.1-5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 5 {
		t.Errorf("expected 5 hosts, got %d", len(hosts))
	}
}

func TestParseHostsInvalidCIDR(t *testing.T) {
	_, err := parseHosts("invalid/24")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestParseHostsHostname(t *testing.T) {
	hosts, err := parseHosts("server.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "server.local" {
		t.Errorf("expected [server.local], got %v", hosts)
	}
}

func TestParsePortsSingle(t *testing.T) {
	ports, err := parsePorts("80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 80 {
		t.Errorf("expected [80], got %v", ports)
	}
}

func TestParsePortsRange(t *testing.T) {
	ports, err := parsePorts("80-85")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 6 {
		t.Errorf("expected 6 ports (80-85), got %d", len(ports))
	}
}

func TestParsePortsMixed(t *testing.T) {
	ports, err := parsePorts("22,80,443,8080-8082")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 6 {
		t.Errorf("expected 6 ports, got %d: %v", len(ports), ports)
	}
}

func TestParsePortsInvalidRange(t *testing.T) {
	_, err := parsePorts("100-50")
	if err == nil {
		t.Error("expected error for reversed range")
	}
}

func TestParsePortsOutOfRange(t *testing.T) {
	_, err := parsePorts("99999")
	if err == nil {
		t.Error("expected error for port > 65535")
	}
}

func TestParsePortsTooLargeRange(t *testing.T) {
	_, err := parsePorts("1-20000")
	if err == nil {
		t.Error("expected error for range > 10000")
	}
}

func TestParsePortsDedup(t *testing.T) {
	ports, err := parsePorts("80,80,80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 {
		t.Errorf("expected 1 port (deduped), got %d", len(ports))
	}
}

func TestPortScanKnownService(t *testing.T) {
	tests := map[int]string{
		22:  "SSH",
		80:  "HTTP",
		443: "HTTPS",
		445: "SMB",
		12345: "",
	}
	for port, expected := range tests {
		got := knownService(port)
		if got != expected {
			t.Errorf("knownService(%d) = %q, want %q", port, got, expected)
		}
	}
}

func TestIncIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1", "192.168.1.2"},
		{"192.168.1.255", "192.168.2.0"},
	}
	for _, tc := range tests {
		ip := make([]byte, 4)
		copy(ip, []byte{192, 168, 1, 1})
		if tc.input == "192.168.1.255" {
			ip[3] = 255
		}
		incIP(ip)
		got := make([]byte, 4)
		copy(got, ip)
		// Just check the increment happened
		if tc.input == "192.168.1.1" && ip[3] != 2 {
			t.Errorf("expected last octet 2, got %d", ip[3])
		}
		if tc.input == "192.168.1.255" && ip[2] != 2 {
			t.Errorf("expected third octet 2 after overflow, got %d", ip[2])
		}
	}
}
