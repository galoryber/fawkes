package agentfunctions

import (
	"strings"
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

// --- extractK8sSecretCreds ---

func TestExtractK8sSecretCreds_Password(t *testing.T) {
	out := `=== Secret: db-creds (type: Opaque) ===

[password]
super-secret-pw

[username]
dbadmin
`
	got := extractK8sSecretCreds(out)
	// password is a credential key, username is not.
	if len(got) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(got), got)
	}
	if got[0].Key != "password" || got[0].Value != "super-secret-pw" {
		t.Errorf("got %+v", got[0])
	}
	if got[0].SecretName != "db-creds" || got[0].SecretType != "Opaque" {
		t.Errorf("header parse failed: %+v", got[0])
	}
}

func TestExtractK8sSecretCreds_SubstringMatch(t *testing.T) {
	out := `=== Secret: app-creds (type: Opaque) ===

[mysql_password]
hunter2

[db-password]
hunter3

[notes]
this is just text
`
	got := extractK8sSecretCreds(out)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(got), got)
	}
}

func TestExtractK8sSecretCreds_JWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.aBcDeF1234567890XYZ"
	out := `=== Secret: sa-token (type: kubernetes.io/service-account-token) ===

[auth-token]
` + jwt + `

[notes]
just text
`
	got := extractK8sSecretCreds(out)
	if len(got) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(got), got)
	}
	if got[0].Key != "auth-token" || got[0].Value != jwt {
		t.Errorf("got %+v", got[0])
	}
}

func TestExtractK8sSecretCreds_DockerConfig(t *testing.T) {
	out := `=== Secret: registry-creds (type: kubernetes.io/dockerconfigjson) ===

[.dockerconfigjson]
{"auths":{"registry.example.com":{"auth":"YWRtaW46cGFzcw=="}}}
`
	got := extractK8sSecretCreds(out)
	if len(got) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(got), got)
	}
	if got[0].Key != ".dockerconfigjson" {
		t.Errorf("got key %q", got[0].Key)
	}
}

func TestExtractK8sSecretCreds_SkipsPlainCert(t *testing.T) {
	out := `=== Secret: tls-secret (type: kubernetes.io/tls) ===

[tls.crt]
-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIIB3l8E9d...
-----END CERTIFICATE-----

[tls.key]
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAg...
-----END PRIVATE KEY-----
`
	got := extractK8sSecretCreds(out)
	// tls.crt is not a credential key, tls.key is.
	if len(got) != 1 {
		t.Fatalf("got %d, want 1 (tls.key only): %+v", len(got), got)
	}
	if got[0].Key != "tls.key" {
		t.Errorf("got %+v", got[0])
	}
}

func TestExtractK8sSecretCreds_SkipsLargeValue(t *testing.T) {
	bigVal := strings.Repeat("a", 5000)
	out := `=== Secret: huge (type: Opaque) ===

[token]
` + bigVal + `

[password]
small-one
`
	got := extractK8sSecretCreds(out)
	// token (>4KiB) skipped; password kept.
	if len(got) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(got), got)
	}
	if got[0].Key != "password" {
		t.Errorf("got %+v", got[0])
	}
}

func TestExtractK8sSecretCreds_NoSecretBanner(t *testing.T) {
	// Listing output (no "=== Secret:" header) → no extraction.
	out := `=== KUBERNETES SECRETS (namespace: default) ===

  db-creds   Opaque   keys:[password,username]
  Total: 1 secret(s)
`
	got := extractK8sSecretCreds(out)
	if len(got) != 0 {
		t.Errorf("listing output should produce no creds, got %d", len(got))
	}
}

func TestExtractK8sSecretCreds_Empty(t *testing.T) {
	if got := extractK8sSecretCreds(""); len(got) != 0 {
		t.Errorf("empty input should produce no creds, got %d", len(got))
	}
}

func TestParseK8sSecretHeader_WithType(t *testing.T) {
	name, typ := parseK8sSecretHeader("=== Secret: db-creds (type: Opaque) ===\n")
	if name != "db-creds" || typ != "Opaque" {
		t.Errorf("got name=%q type=%q", name, typ)
	}
}

func TestParseK8sSecretHeader_WithoutType(t *testing.T) {
	name, typ := parseK8sSecretHeader("=== Secret: my-secret ===\n")
	if name != "my-secret" || typ != "" {
		t.Errorf("got name=%q type=%q", name, typ)
	}
}

func TestParseK8sSecretHeader_Missing(t *testing.T) {
	name, typ := parseK8sSecretHeader("no banner here\n")
	if name != "" || typ != "" {
		t.Errorf("got name=%q type=%q", name, typ)
	}
}

func TestLooksLikeJWT_Valid(t *testing.T) {
	if !looksLikeJWT("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.aBcDeF1234567890XYZ") {
		t.Errorf("valid JWT shape not detected")
	}
}

func TestLooksLikeJWT_TwoSegments(t *testing.T) {
	if looksLikeJWT("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9") {
		t.Errorf("2-segment string should NOT match")
	}
}

func TestLooksLikeJWT_WithSpaces(t *testing.T) {
	if looksLikeJWT("eyJhbGciOiJIUzI1NiJ9 eyJzdWIiOiIxMjM0NSJ9 sig") {
		t.Errorf("whitespace should disqualify")
	}
}

func TestLooksLikeJWT_NonBase64(t *testing.T) {
	if looksLikeJWT("hello.world.foo!") {
		t.Errorf("non-base64 chars should disqualify")
	}
}

func TestCredTypeForK8sSecretKey(t *testing.T) {
	cases := map[string]string{
		"password":             "plaintext",
		"token":                "plaintext",
		"tls.key":              "key",
		"ssh-privatekey":       "key",
		"id_rsa":               "key",
		".dockerconfigjson":    "service_account",
		"service-account.json": "service_account",
		"kubeconfig":           "service_account",
		"random-key":           "plaintext",
	}
	for k, want := range cases {
		if got := credTypeForK8sSecretKey(k); got != want {
			t.Errorf("credTypeForK8sSecretKey(%q) = %q, want %q", k, got, want)
		}
	}
}
