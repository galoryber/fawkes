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

// --- countRBACFindings ---

func TestCountRBACFindings_MixedSeverities(t *testing.T) {
	out := `--- Privilege Escalation Findings (3) ---
  [CRIT] ServiceAccount/robot@kube-system
        via ClusterRoleBinding/ca-bind → ClusterRole/cluster-admin
        binds subject to cluster-admin (root-equivalent)
  [WARN] User/alice
        via RoleBinding/ns-binding@prod → Role/secret-reader
        read every secret in scope (service-account tokens, registry creds, app secrets)
  [INFO] User/bob
        via ClusterRoleBinding/role-x → ClusterRole/role-x
        info path here`
	crit, warn := countRBACFindings(out)
	if crit != 1 {
		t.Errorf("crit = %d, want 1", crit)
	}
	if warn != 1 {
		t.Errorf("warn = %d, want 1", warn)
	}
}

func TestCountRBACFindings_NoFindings(t *testing.T) {
	out := `--- Privilege Escalation Findings (0) ---
  None detected. RBAC posture looks reasonable for the scoped namespaces.`
	crit, warn := countRBACFindings(out)
	if crit != 0 || warn != 0 {
		t.Errorf("got crit=%d warn=%d, want 0/0", crit, warn)
	}
}

func TestCountRBACFindings_MultipleCrit(t *testing.T) {
	out := `  [CRIT] a
  [CRIT] b
  [CRIT] c
  [WARN] d
  [WARN] e`
	crit, warn := countRBACFindings(out)
	if crit != 3 {
		t.Errorf("crit = %d, want 3", crit)
	}
	if warn != 2 {
		t.Errorf("warn = %d, want 2", warn)
	}
}

// --- countK8sNodes ---

func TestCountK8sNodes_FromHeader(t *testing.T) {
	out := `=== KUBERNETES NODE ENUMERATION ===

API Server: https://10.0.0.1:6443
Nodes:      4

[*] node-01
    Roles: control-plane`
	if got := countK8sNodes(out); got != 4 {
		t.Errorf("got %d, want 4", got)
	}
}

func TestCountK8sNodes_FromBulletFallback(t *testing.T) {
	// No "Nodes:" header — fall back to counting "[*] " lines.
	out := `[*] node-01
    Ready: True
[*] node-02
    Ready: True
[*] node-03
    Ready: False`
	if got := countK8sNodes(out); got != 3 {
		t.Errorf("got %d, want 3", got)
	}
}

func TestCountK8sNodes_Empty(t *testing.T) {
	if got := countK8sNodes(""); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// --- countEtcdUnauth ---

func TestCountEtcdUnauth_AllUnauth(t *testing.T) {
	out := `Endpoints to probe: 3

--- Probe Results ---
  [UNAUTH] https://10.0.0.5:2379
        etcdserver=3.5.10 cluster=3.5.0
  [UNAUTH] https://10.0.0.6:2379
        etcdserver=3.5.10 cluster=3.5.0
  [UNAUTH] http://127.0.0.1:2379
        etcdserver=3.5.10 cluster=3.5.0`
	unauth, total := countEtcdUnauth(out)
	if unauth != 3 {
		t.Errorf("unauth = %d, want 3", unauth)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
}

func TestCountEtcdUnauth_MixedResults(t *testing.T) {
	out := `Endpoints to probe: 4

--- Probe Results ---
  [UNAUTH] http://127.0.0.1:2379
        etcdserver=3.5.10 cluster=3.5.0
  [AUTH-REQUIRED] https://10.0.0.5:2379
        HTTP 401
  [TLS-REQUIRED] https://10.0.0.6:2379
        remote error: tls: bad certificate
  [UNREACHABLE] https://10.0.0.7:2379
        dial tcp 10.0.0.7:2379: i/o timeout`
	unauth, total := countEtcdUnauth(out)
	if unauth != 1 {
		t.Errorf("unauth = %d, want 1", unauth)
	}
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
}

func TestCountEtcdUnauth_NoUnauth(t *testing.T) {
	out := `Endpoints to probe: 2
  [AUTH-REQUIRED] https://10.0.0.5:2379
  [UNREACHABLE] https://10.0.0.6:2379`
	unauth, total := countEtcdUnauth(out)
	if unauth != 0 {
		t.Errorf("unauth = %d, want 0", unauth)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
}

func TestCountEtcdUnauth_Empty(t *testing.T) {
	unauth, total := countEtcdUnauth("")
	if unauth != 0 || total != 0 {
		t.Errorf("got unauth=%d total=%d, want 0/0", unauth, total)
	}
}
