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
	// /8 network would exceed 65536
	params, _ := json.Marshal(pingArgs{Hosts: "10.0.0.0/8"})
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
