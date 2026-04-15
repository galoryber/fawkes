package agentfunctions

import (
	"testing"
)

func TestDetectEscapeVectors_DockerSocket(t *testing.T) {
	input := "[+] Docker socket found at /var/run/docker.sock"
	found := detectEscapeVectors(input)
	if len(found) != 1 || found[0] != "Docker socket" {
		t.Errorf("expected [Docker socket], got %v", found)
	}
}

func TestDetectEscapeVectors_Multiple(t *testing.T) {
	input := `[+] Container is privileged (--privileged flag)
[+] cgroup v1 writable
[+] cap_sys_admin capability present`

	found := detectEscapeVectors(input)
	if len(found) != 3 {
		t.Fatalf("expected 3 vectors, got %d: %v", len(found), found)
	}
}

func TestDetectEscapeVectors_None(t *testing.T) {
	input := "[-] No escape vectors detected. Container appears hardened."
	found := detectEscapeVectors(input)
	if len(found) != 0 {
		t.Errorf("expected 0 vectors, got %d: %v", len(found), found)
	}
}

func TestDetectEscapeVectors_CaseInsensitive(t *testing.T) {
	input := "DOCKER SOCKET available\nNSENTER binary found"
	found := detectEscapeVectors(input)
	if len(found) != 2 {
		t.Errorf("expected 2 vectors (case insensitive), got %d: %v", len(found), found)
	}
}

func TestDetectEscapeVectors_AllVectors(t *testing.T) {
	input := "Docker socket, cgroup, nsenter, mount-host, privileged, cap_sys_admin, host PID"
	found := detectEscapeVectors(input)
	if len(found) != 7 {
		t.Errorf("expected 7 vectors, got %d: %v", len(found), found)
	}
}

func TestDetectEscapeVectors_Empty(t *testing.T) {
	found := detectEscapeVectors("")
	if len(found) != 0 {
		t.Errorf("expected 0 vectors, got %d", len(found))
	}
}
