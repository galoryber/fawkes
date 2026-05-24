package commands

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestSshFindKeysInDir_Empty(t *testing.T) {
	// Non-existent dir returns empty slice
	keys := sshFindKeysInDir("/tmp/does-not-exist-ever-ever")
	if len(keys) != 0 {
		t.Errorf("sshFindKeysInDir(nonexistent) = %v, want empty", keys)
	}
}

func TestSshDiscoverPrivateKeys_NoPath(t *testing.T) {
	// Must not panic. May return empty if no keys exist in test environment.
	keys := sshDiscoverPrivateKeys("")
	_ = keys // result is environment-dependent; just ensure no panic
}

func TestSshDiscoverPrivateKeys_ExplicitFile(t *testing.T) {
	// Passing a non-existent explicit file returns empty slice
	keys := sshDiscoverPrivateKeys("/tmp/definitely-not-a-real-key-file.pem")
	if len(keys) != 0 {
		t.Errorf("sshDiscoverPrivateKeys(missing file) = %v, want empty", keys)
	}
}

func TestSshScanReachable_NoHosts(t *testing.T) {
	reachable := sshScanReachable(nil, 22, time.Millisecond*100)
	if len(reachable) != 0 {
		t.Errorf("sshScanReachable(nil) = %v, want empty", reachable)
	}
}

func TestSshScanReachable_UnreachableHosts(t *testing.T) {
	// 192.0.2.x is TEST-NET (RFC 5737), guaranteed unreachable
	hosts := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	reachable := sshScanReachable(hosts, 22, 100*time.Millisecond)
	if len(reachable) != 0 {
		t.Errorf("sshScanReachable(test-net) = %v, want empty", reachable)
	}
}

func TestSshScanReachable_LocalhostOpenPort(t *testing.T) {
	// Start a TCP listener on localhost to simulate an open SSH port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen on local port:", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	hosts := []string{"127.0.0.1"}
	reachable := sshScanReachable(hosts, addr.Port, time.Second)
	if len(reachable) != 1 || reachable[0] != "127.0.0.1" {
		t.Errorf("sshScanReachable(localhost open port) = %v, want [127.0.0.1]", reachable)
	}
}

func TestSshKeysFindReachable_NoTargets(t *testing.T) {
	result := sshKeysFindReachable(sshKeysArgs{Action: "find-reachable"})
	if result.Status == "success" {
		t.Error("sshKeysFindReachable with no targets should fail")
	}
}

func TestSshKeysTryKeys_NoHost(t *testing.T) {
	result := sshKeysTryKeys(sshKeysArgs{Action: "try-keys"})
	if result.Status == "success" {
		t.Error("sshKeysTryKeys with no host should fail")
	}
}

func TestSshKeysTryKeys_NoKeys(t *testing.T) {
	// Non-existent path → no keys → error result
	result := sshKeysTryKeys(sshKeysArgs{
		Action: "try-keys",
		Host:   "192.0.2.1",
		Path:   "/tmp/no-keys-here-at-all-xyz",
	})
	if result.Status == "success" {
		t.Error("sshKeysTryKeys with no keys should fail")
	}
	if !strings.Contains(result.Output, "No SSH private keys") {
		t.Errorf("unexpected error output: %q", result.Output)
	}
}

func TestSshKeysAutoMove_NoTargets(t *testing.T) {
	result := sshKeysAutoMove(sshKeysArgs{Action: "auto-move"})
	if result.Status == "success" {
		t.Error("sshKeysAutoMove with no targets should fail")
	}
}

func TestSshKeysAutoMove_UnreachableSubnet(t *testing.T) {
	// 192.0.2.0/30 — TEST-NET, guaranteed unreachable, only 2 hosts
	result := sshKeysAutoMove(sshKeysArgs{
		Action:  "auto-move",
		Targets: "192.0.2.1,192.0.2.2",
		Port:    22,
	})
	if result.Status != "success" {
		t.Errorf("sshKeysAutoMove should succeed (reporting no reachable), got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "0/2 hosts have SSH open") && !strings.Contains(result.Output, "0/") {
		// May say "No reachable SSH hosts found" or similar
		if !strings.Contains(result.Output, "No reachable") {
			t.Logf("output: %s", result.Output)
		}
	}
}
