package commands

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPingCommandName(t *testing.T) {
	cmd := &PingCommand{}
	if cmd.Name() != "ping" {
		t.Errorf("expected 'ping', got '%s'", cmd.Name())
	}
}

func TestPingEmptyParams(t *testing.T) {
	cmd := &PingCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestPingMissingHosts(t *testing.T) {
	cmd := &PingCommand{}
	params, _ := json.Marshal(pingArgs{Hosts: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status for empty hosts, got %s", result.Status)
	}
}

func TestPingTooManyHosts(t *testing.T) {
	cmd := &PingCommand{}
	// /15 gives ~131K hosts which exceeds the 65536 limit but expands much
	// faster than a /8 (16M IPs takes ~9s to iterate vs ~0.5s for /15).
	params, _ := json.Marshal(pingArgs{Hosts: "10.0.0.0/15"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for too many hosts, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "too many hosts") {
		t.Errorf("expected 'too many hosts' in output, got: %s", result.Output)
	}
}

func TestPingLocalhost(t *testing.T) {
	// Start a TCP listener to ping against
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot create test listener")
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	cmd := &PingCommand{}
	params, _ := json.Marshal(pingArgs{
		Hosts:   "127.0.0.1",
		Port:    addr.Port,
		Timeout: 500,
		Threads: 1,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "1/1 hosts alive") {
		t.Errorf("expected 1/1 hosts alive, got: %s", result.Output)
	}
}

func TestPingUnreachableHost(t *testing.T) {
	cmd := &PingCommand{}
	params, _ := json.Marshal(pingArgs{
		Hosts:   "127.0.0.1",
		Port:    1, // port 1 likely not listening
		Timeout: 200,
		Threads: 1,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success status, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "0/1 hosts alive") {
		t.Errorf("expected 0/1 hosts alive, got: %s", result.Output)
	}
}

func TestExpandHostsCIDR(t *testing.T) {
	ips := expandHosts("192.168.1.0/30")
	// /30 = 4 IPs, minus network and broadcast = 2
	if len(ips) != 2 {
		t.Errorf("expected 2 hosts from /30, got %d: %v", len(ips), ips)
	}
}

func TestExpandHostsDashRange(t *testing.T) {
	ips := expandHosts("10.0.0.1-5")
	if len(ips) != 5 {
		t.Errorf("expected 5 hosts, got %d: %v", len(ips), ips)
	}
	if ips[0] != "10.0.0.1" || ips[4] != "10.0.0.5" {
		t.Errorf("unexpected range: %v", ips)
	}
}

func TestExpandHostsComma(t *testing.T) {
	ips := expandHosts("10.0.0.1,10.0.0.2,10.0.0.3")
	if len(ips) != 3 {
		t.Errorf("expected 3 hosts, got %d", len(ips))
	}
}

func TestExpandHostsSingle(t *testing.T) {
	ips := expandHosts("192.168.1.100")
	if len(ips) != 1 || ips[0] != "192.168.1.100" {
		t.Errorf("expected single host, got %v", ips)
	}
}

func TestExpandHostsHostname(t *testing.T) {
	ips := expandHosts("dc01")
	if len(ips) != 1 || ips[0] != "dc01" {
		t.Errorf("expected hostname passthrough, got %v", ips)
	}
}

// --- expandCIDR edge case tests ---

func TestExpandCIDR_Slash32(t *testing.T) {
	ips := expandCIDR("10.0.0.5/32")
	// /32 = 1 IP, but len(ips) <= 2 path skips stripping
	if len(ips) != 1 {
		t.Errorf("expected 1 host from /32, got %d: %v", len(ips), ips)
	}
	if len(ips) > 0 && ips[0] != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %s", ips[0])
	}
}

func TestExpandCIDR_Slash31(t *testing.T) {
	ips := expandCIDR("10.0.0.0/31")
	// /31 = 2 IPs, len <= 2 so no stripping of network/broadcast
	if len(ips) != 2 {
		t.Errorf("expected 2 hosts from /31, got %d: %v", len(ips), ips)
	}
}

func TestExpandCIDR_Slash24(t *testing.T) {
	ips := expandCIDR("192.168.1.0/24")
	// /24 = 256 IPs minus network and broadcast = 254
	if len(ips) != 254 {
		t.Errorf("expected 254 hosts from /24, got %d", len(ips))
	}
	if len(ips) > 0 && ips[0] != "192.168.1.1" {
		t.Errorf("expected first host 192.168.1.1, got %s", ips[0])
	}
	if len(ips) > 253 && ips[253] != "192.168.1.254" {
		t.Errorf("expected last host 192.168.1.254, got %s", ips[253])
	}
}

func TestExpandCIDR_InvalidCIDR(t *testing.T) {
	ips := expandCIDR("not-a-cidr")
	if len(ips) != 0 {
		t.Errorf("expected 0 hosts for invalid CIDR, got %d", len(ips))
	}
}

func TestExpandCIDR_Slash29(t *testing.T) {
	ips := expandCIDR("10.0.0.0/29")
	// /29 = 8 IPs minus network and broadcast = 6
	if len(ips) != 6 {
		t.Errorf("expected 6 hosts from /29, got %d: %v", len(ips), ips)
	}
}

// --- expandDashRange edge case tests ---

func TestExpandDashRange_StartGreaterThanEnd(t *testing.T) {
	ips := expandDashRange("10.0.0.100-50")
	if len(ips) != 0 {
		t.Errorf("expected 0 hosts for reversed range, got %d: %v", len(ips), ips)
	}
}

func TestExpandDashRange_EndGreaterThan255(t *testing.T) {
	ips := expandDashRange("10.0.0.1-300")
	if len(ips) != 0 {
		t.Errorf("expected 0 hosts for end > 255, got %d: %v", len(ips), ips)
	}
}

func TestExpandDashRange_NegativeStart(t *testing.T) {
	ips := expandDashRange("10.0.0.-1-5")
	// rangePart is "-1-5", first dash at index 0, Sscanf("") fails → passthrough
	if len(ips) != 1 {
		t.Errorf("expected 1 passthrough for unparseable range, got %d: %v", len(ips), ips)
	}
}

func TestExpandDashRange_NoDot(t *testing.T) {
	ips := expandDashRange("nohost")
	// No dot → returns [spec]
	if len(ips) != 1 || ips[0] != "nohost" {
		t.Errorf("expected passthrough, got %v", ips)
	}
}

func TestExpandDashRange_NoDashInLastOctet(t *testing.T) {
	ips := expandDashRange("10.0.0.5")
	// Has dot but no dash after last dot → returns [spec]
	if len(ips) != 1 || ips[0] != "10.0.0.5" {
		t.Errorf("expected passthrough, got %v", ips)
	}
}

func TestExpandDashRange_SingleHost(t *testing.T) {
	ips := expandDashRange("10.0.0.5-5")
	if len(ips) != 1 || ips[0] != "10.0.0.5" {
		t.Errorf("expected 1 host, got %v", ips)
	}
}

func TestExpandDashRange_FullOctet(t *testing.T) {
	ips := expandDashRange("10.0.0.0-255")
	if len(ips) != 256 {
		t.Errorf("expected 256 hosts for full octet range, got %d", len(ips))
	}
}

func TestExpandDashRange_InvalidStartFormat(t *testing.T) {
	ips := expandDashRange("10.0.0.abc-5")
	// Sscanf fails on "abc" → returns [spec]
	if len(ips) != 1 {
		t.Errorf("expected passthrough for invalid start, got %v", ips)
	}
}

func TestExpandDashRange_InvalidEndFormat(t *testing.T) {
	ips := expandDashRange("10.0.0.1-abc")
	// Sscanf fails on "abc" → returns [spec]
	if len(ips) != 1 {
		t.Errorf("expected passthrough for invalid end, got %v", ips)
	}
}

// --- pingIncIP tests ---

func TestPingIncIP_Simple(t *testing.T) {
	ip := net.ParseIP("10.0.0.1").To4()
	pingIncIP(ip)
	if ip.String() != "10.0.0.2" {
		t.Errorf("expected 10.0.0.2, got %s", ip.String())
	}
}

func TestPingIncIP_CarryLastOctet(t *testing.T) {
	ip := net.ParseIP("10.0.0.255").To4()
	pingIncIP(ip)
	if ip.String() != "10.0.1.0" {
		t.Errorf("expected 10.0.1.0, got %s", ip.String())
	}
}

func TestPingIncIP_CarryTwoOctets(t *testing.T) {
	ip := net.ParseIP("10.0.255.255").To4()
	pingIncIP(ip)
	if ip.String() != "10.1.0.0" {
		t.Errorf("expected 10.1.0.0, got %s", ip.String())
	}
}

func TestPingIncIP_CarryThreeOctets(t *testing.T) {
	ip := net.ParseIP("10.255.255.255").To4()
	pingIncIP(ip)
	if ip.String() != "11.0.0.0" {
		t.Errorf("expected 11.0.0.0, got %s", ip.String())
	}
}

// --- expandHosts mixed input tests ---

func TestExpandHostsEmpty(t *testing.T) {
	ips := expandHosts("")
	if len(ips) != 0 {
		t.Errorf("expected 0 hosts for empty input, got %d", len(ips))
	}
}

func TestExpandHostsMixed(t *testing.T) {
	ips := expandHosts("10.0.0.1, 10.0.0.5-7, 192.168.1.0/30")
	// 1 + 3 + 2 = 6
	if len(ips) != 6 {
		t.Errorf("expected 6 hosts for mixed input, got %d: %v", len(ips), ips)
	}
}

func TestExpandHostsWhitespace(t *testing.T) {
	ips := expandHosts("  10.0.0.1 , 10.0.0.2 , ")
	if len(ips) != 2 {
		t.Errorf("expected 2 hosts with whitespace, got %d: %v", len(ips), ips)
	}
}

func TestPingThreadsCapped(t *testing.T) {
	cmd := &PingCommand{}
	params, _ := json.Marshal(pingArgs{
		Hosts:   "127.0.0.1",
		Port:    1,
		Timeout: 100,
		Threads: 500, // should be capped to 100
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should still work, just capped
	if !strings.Contains(result.Output, "100 threads") {
		t.Errorf("expected threads capped to 100, got: %s", result.Output)
	}
}
