package commands

// container_escape_k8s_helpers.go contains pure helpers for K8s RBAC privilege
// escalation analysis and node summarization. No build tags — these are
// cross-platform testable so coverage runs in CI on Linux without needing
// access to a real K8s API server.
//
// Used by container_escape_k8s_rbac.go and container_escape_k8s_nodes.go
// (Linux-only) but the parsing/scoring logic lives here.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// k8sRBACRule mirrors the K8s PolicyRule shape returned in (Cluster)Role.rules[].
type k8sRBACRule struct {
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	Verbs         []string `json:"verbs"`
	ResourceNames []string `json:"resourceNames"`
}

// k8sRBACSubject mirrors the Subject shape in (Cluster)RoleBinding.subjects[].
type k8sRBACSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// k8sRBACRoleRef mirrors the RoleRef shape in (Cluster)RoleBinding.roleRef.
type k8sRBACRoleRef struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	APIGroup string `json:"apiGroup"`
}

// k8sRBACBinding is a denormalised view of either a ClusterRoleBinding or
// a namespaced RoleBinding. ClusterScoped=true means there's no namespace
// constraint on the rule the binding references.
type k8sRBACBinding struct {
	Kind         string           // "ClusterRoleBinding" or "RoleBinding"
	Name         string           // binding name (metadata.name)
	Namespace    string           // empty for ClusterRoleBindings
	ClusterScope bool             // true for ClusterRoleBindings or namespaced RBs that ref a ClusterRole
	Subjects     []k8sRBACSubject // who the binding applies to
	RoleRef      k8sRBACRoleRef   // role granted by the binding
}

// k8sRBACFinding is one detected privilege-escalation path or risky grant.
type k8sRBACFinding struct {
	Severity string // "crit", "warn", "info"
	Subject  string // formatted "Kind/Name[@namespace]" for the subject of the finding
	Binding  string // formatted "Kind/Name[@namespace]" pointing to the binding
	Role     string // role name being granted
	Reason   string // human-readable description of why this is risky
}

// dangerousResourceVerbs maps (resource → set of verbs) to a human reason
// explaining the escalation path. Resource match is case-insensitive and
// applies when the rule explicitly names the resource (not just `*`).
var dangerousResourceVerbs = []struct {
	Resource string
	Verbs    []string
	Reason   string
}{
	// pod-level execution channels
	{"pods/exec", []string{"create", "get"}, "exec into any pod in scope (root-equivalent if pod is privileged)"},
	{"pods/attach", []string{"create", "get"}, "attach to any pod's TTY (interactive shell capture)"},
	{"pods/portforward", []string{"create", "get"}, "port-forward to any pod (data-plane MITM)"},
	{"pods/proxy", []string{"create", "get"}, "proxy traffic via any pod"},
	// pod creation = arbitrary code execution on cluster nodes
	{"pods", []string{"create", "update", "patch"}, "create/modify pods (run arbitrary containers, optionally privileged or hostPath-mounted)"},
	{"deployments", []string{"create", "update", "patch"}, "create/modify deployments (indirect pod creation)"},
	{"daemonsets", []string{"create", "update", "patch"}, "create/modify daemonsets (per-node pod placement = host compromise)"},
	{"statefulsets", []string{"create", "update", "patch"}, "create/modify statefulsets (persistent storage + identity attack surface)"},
	{"jobs", []string{"create", "update", "patch"}, "create/modify jobs (one-shot container exec)"},
	{"cronjobs", []string{"create", "update", "patch"}, "create/modify cronjobs (scheduled persistence)"},
	// credentials and identity
	{"secrets", []string{"get", "list", "watch"}, "read every secret in scope (service-account tokens, registry creds, app secrets)"},
	{"serviceaccounts", []string{"impersonate"}, "impersonate any service account (token-free identity bypass)"},
	{"serviceaccounts/token", []string{"create"}, "mint tokens for any service account (no-rotation credential theft)"},
	// node + cluster control
	{"nodes", []string{"update", "patch", "create", "delete"}, "modify nodes (taints, labels, scheduling) — full cluster control"},
	{"nodes/proxy", []string{"create", "get"}, "proxy through kubelet API (run pods, read logs without RBAC)"},
	// RBAC self-escalation
	{"roles", []string{"escalate", "bind"}, "escalate or bind roles (grant yourself arbitrary verbs)"},
	{"clusterroles", []string{"escalate", "bind"}, "escalate or bind cluster-roles (grant cluster-admin to yourself)"},
	{"rolebindings", []string{"create", "update", "patch"}, "create/modify rolebindings (grant any role to any subject)"},
	{"clusterrolebindings", []string{"create", "update", "patch"}, "create/modify cluster-rolebindings (cluster-admin self-grant)"},
	// kubelet & control plane
	{"certificatesigningrequests/approval", []string{"create", "update"}, "auto-approve CSRs (mint kubelet certs for arbitrary nodes)"},
	{"validatingwebhookconfigurations", []string{"create", "update", "patch"}, "install admission webhooks (intercept and modify any API call)"},
	{"mutatingwebhookconfigurations", []string{"create", "update", "patch"}, "install mutating webhooks (rewrite pod specs cluster-wide)"},
}

// rbacRuleIsDangerous returns (true, reason) if the rule grants an
// escalation-class permission. The first matching reason is returned so
// findings stay concise.
//
// Detection rules, in order:
//  1. Verbs contains "*" AND Resources contains "*"           → "cluster-admin equivalent"
//  2. Verbs contains "*" AND specific dangerous resource      → "all verbs on <resource>"
//  3. Resources contains "*" AND specific dangerous verb      → "<verb> on every resource"
//  4. Specific resource+verb match in dangerousResourceVerbs  → tailored reason
func rbacRuleIsDangerous(rule k8sRBACRule) (bool, string) {
	verbs := lowerSet(rule.Verbs)
	resources := lowerSet(rule.Resources)

	hasVerbWildcard := verbs["*"]
	hasResourceWildcard := resources["*"]

	if hasVerbWildcard && hasResourceWildcard {
		return true, "cluster-admin equivalent: rule grants all verbs on all resources"
	}
	if hasVerbWildcard {
		// Wildcard verbs against a specific resource — equivalent to "*/<res>".
		for res := range resources {
			if res == "" {
				continue
			}
			return true, fmt.Sprintf("all verbs on %s (resource wildcard verbs)", res)
		}
	}
	if hasResourceWildcard {
		// Wildcard resources, specific verb — surface if the verb is itself in
		// a sensitive set (create/delete/update/patch/* on everything).
		for v := range verbs {
			switch v {
			case "create", "update", "patch", "delete", "deletecollection", "impersonate", "escalate", "bind":
				return true, fmt.Sprintf("%s on every resource (resource wildcard)", v)
			}
		}
	}

	// Specific resource+verb intersections.
	for _, rv := range dangerousResourceVerbs {
		if !resources[strings.ToLower(rv.Resource)] {
			continue
		}
		for _, v := range rv.Verbs {
			if verbs[strings.ToLower(v)] {
				return true, rv.Reason
			}
		}
	}
	return false, ""
}

// bindingIsClusterAdmin returns true if the binding targets the well-known
// cluster-admin ClusterRole or grants membership in system:masters.
func bindingIsClusterAdmin(b k8sRBACBinding) bool {
	if strings.EqualFold(b.RoleRef.Kind, "ClusterRole") && strings.EqualFold(b.RoleRef.Name, "cluster-admin") {
		return true
	}
	for _, s := range b.Subjects {
		if strings.EqualFold(s.Kind, "Group") && strings.EqualFold(s.Name, "system:masters") {
			return true
		}
	}
	return false
}

// formatRBACSubject renders a subject as "Kind/Name[@namespace]". Used as a
// stable key for findings.
func formatRBACSubject(s k8sRBACSubject) string {
	if s.Namespace == "" {
		return fmt.Sprintf("%s/%s", s.Kind, s.Name)
	}
	return fmt.Sprintf("%s/%s@%s", s.Kind, s.Name, s.Namespace)
}

// formatRBACBinding renders a binding for human display.
func formatRBACBinding(b k8sRBACBinding) string {
	if b.Namespace == "" {
		return fmt.Sprintf("%s/%s", b.Kind, b.Name)
	}
	return fmt.Sprintf("%s/%s@%s", b.Kind, b.Name, b.Namespace)
}

// summarizeRBACPrivesc cross-references the binding set against the rules
// each referenced role grants, and produces one finding per dangerous
// subject/binding pair. roleRules maps "<scope>/<rolename>" to the rule
// list for that role, where scope is "cluster" for ClusterRoles or the
// namespace name for namespaced Roles.
//
// Findings are returned sorted (crit first, then by subject) so the
// human-facing output is deterministic across runs.
func summarizeRBACPrivesc(bindings []k8sRBACBinding, roleRules map[string][]k8sRBACRule) []k8sRBACFinding {
	var findings []k8sRBACFinding
	for _, b := range bindings {
		if bindingIsClusterAdmin(b) {
			for _, s := range b.Subjects {
				findings = append(findings, k8sRBACFinding{
					Severity: "crit",
					Subject:  formatRBACSubject(s),
					Binding:  formatRBACBinding(b),
					Role:     fmt.Sprintf("%s/%s", b.RoleRef.Kind, b.RoleRef.Name),
					Reason:   "binds subject to cluster-admin (root-equivalent)",
				})
			}
			continue
		}

		key := rbacRuleLookupKey(b)
		rules, ok := roleRules[key]
		if !ok {
			continue
		}
		for _, rule := range rules {
			ok, reason := rbacRuleIsDangerous(rule)
			if !ok {
				continue
			}
			for _, s := range b.Subjects {
				findings = append(findings, k8sRBACFinding{
					Severity: rbacSeverityFor(reason),
					Subject:  formatRBACSubject(s),
					Binding:  formatRBACBinding(b),
					Role:     fmt.Sprintf("%s/%s", b.RoleRef.Kind, b.RoleRef.Name),
					Reason:   reason,
				})
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return rbacSeverityRank(findings[i].Severity) < rbacSeverityRank(findings[j].Severity)
		}
		if findings[i].Subject != findings[j].Subject {
			return findings[i].Subject < findings[j].Subject
		}
		return findings[i].Reason < findings[j].Reason
	})
	return findings
}

// rbacRuleLookupKey returns the map key used by summarizeRBACPrivesc to
// look up the rules for a binding's referenced role. ClusterRole references
// always use "cluster/<name>"; namespaced Role references use
// "<namespace>/<name>".
func rbacRuleLookupKey(b k8sRBACBinding) string {
	if strings.EqualFold(b.RoleRef.Kind, "ClusterRole") {
		return "cluster/" + b.RoleRef.Name
	}
	if b.Namespace == "" {
		// Namespaced Role referenced by a ClusterRoleBinding is invalid in K8s,
		// but be permissive: treat as cluster-scoped lookup.
		return "cluster/" + b.RoleRef.Name
	}
	return b.Namespace + "/" + b.RoleRef.Name
}

// rbacSeverityFor maps a finding reason to a severity tier.
func rbacSeverityFor(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "cluster-admin"),
		strings.Contains(r, "self-grant"),
		strings.Contains(r, "escalate"),
		strings.Contains(r, "all verbs"),
		strings.Contains(r, "every resource"),
		strings.Contains(r, "mint tokens"),
		strings.Contains(r, "impersonate"):
		return "crit"
	case strings.Contains(r, "exec into"),
		strings.Contains(r, "create/modify"),
		strings.Contains(r, "install"),
		strings.Contains(r, "read every secret"),
		strings.Contains(r, "auto-approve csrs"):
		return "warn"
	default:
		return "info"
	}
}

func rbacSeverityRank(sev string) int {
	switch sev {
	case "crit":
		return 0
	case "warn":
		return 1
	case "info":
		return 2
	}
	return 9
}

// k8sNodeAddress models one entry in node.status.addresses[].
type k8sNodeAddress struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

// k8sNodeTaint models one entry in node.spec.taints[].
type k8sNodeTaint struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Effect string `json:"effect"`
}

// k8sNodeSummary is the flat summary that escapeK8sNodes presents and tests
// can assert against.
type k8sNodeSummary struct {
	Name              string
	Roles             []string
	InternalIP        string
	ExternalIP        string
	Hostname          string
	PodCIDR           string
	KubeletVersion    string
	OSImage           string
	KernelVersion     string
	ContainerRuntime  string
	AllocatableCPU    string
	AllocatableMemory string
	Taints            []string
	Ready             string
}

// formatNodeTaint renders one taint as "key=value:effect" (or "key:effect"
// when value is empty). Stable ordering for tests.
func formatNodeTaint(t k8sNodeTaint) string {
	if t.Value == "" {
		return fmt.Sprintf("%s:%s", t.Key, t.Effect)
	}
	return fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect)
}

// extractNodeRoles pulls role names out of node labels. Roles are encoded as
// `node-role.kubernetes.io/<role>` label keys (empty value); the role name
// is the suffix.
func extractNodeRoles(labels map[string]string) []string {
	var roles []string
	for k := range labels {
		const prefix = "node-role.kubernetes.io/"
		if strings.HasPrefix(k, prefix) {
			roles = append(roles, strings.TrimPrefix(k, prefix))
		}
	}
	sort.Strings(roles)
	return roles
}

// pickAddressByType returns the first address matching the given type
// (case-insensitive). K8s uses "InternalIP", "ExternalIP", "Hostname".
func pickAddressByType(addrs []k8sNodeAddress, typ string) string {
	for _, a := range addrs {
		if strings.EqualFold(a.Type, typ) {
			return a.Address
		}
	}
	return ""
}

// nodeReadyCondition returns "True"/"False"/"Unknown" or "" if the Ready
// condition isn't present. conditions is the raw conditions[] list from
// node.status.
func nodeReadyCondition(conditions []map[string]any) string {
	for _, c := range conditions {
		if t, _ := c["type"].(string); strings.EqualFold(t, "Ready") {
			if s, _ := c["status"].(string); s != "" {
				return s
			}
		}
	}
	return ""
}

// lowerSet returns a set of the lowercased entries in xs.
func lowerSet(xs []string) map[string]bool {
	out := make(map[string]bool, len(xs))
	for _, x := range xs {
		out[strings.ToLower(x)] = true
	}
	return out
}

// --- k8s-etcd discovery / probe helpers ---

// k8sEtcdEndpoint records one discovered etcd client URL plus the in-cluster
// source it was discovered from.
type k8sEtcdEndpoint struct {
	URL    string // canonical "scheme://host:port" — no trailing slash, no path
	Source string // human-readable provenance ("kube-apiserver/--etcd-servers", "etcd-pod/<name>", "default")
}

// k8sEtcdProbeResult captures the outcome of one etcd reachability probe.
type k8sEtcdProbeResult struct {
	URL          string // probed URL
	Status       string // "unauth", "tls-required", "auth-required", "unreachable", "error"
	Detail       string // free-text supplement (version string, error message, HTTP code)
	EtcdServer   string // etcd version from /version when reachable
	EtcdCluster  string // cluster version from /version
	HTTPStatus   int    // last HTTP status code observed (0 if no HTTP response)
	UnauthAccess bool   // true ONLY when an unauthenticated read succeeded
}

// containerIsEtcd returns true when a pod-container name+args pair looks like
// an etcd server. Matches on common naming patterns used by kubeadm and most
// distros: container name == "etcd" OR command/args includes "etcd" with one
// of the etcd-specific listen flags. Case-insensitive.
func containerIsEtcd(name string, command []string, args []string) bool {
	if strings.EqualFold(name, "etcd") {
		return true
	}
	all := append([]string{}, command...)
	all = append(all, args...)
	for _, a := range all {
		la := strings.ToLower(a)
		if strings.Contains(la, "--listen-client-urls") ||
			strings.Contains(la, "--advertise-client-urls") {
			return true
		}
	}
	return false
}

// parseEtcdEndpointsFromArgs scans a command/args slice and returns every
// URL extracted from etcd-related flags. Handles three shapes:
//   - "--flag=value1,value2"           (single token, equals form)
//   - "--flag", "value1,value2"        (two tokens)
//   - "value1,value2" embedded in either of the above
//
// Flags inspected (case-insensitive):
//
//	--etcd-servers           (kube-apiserver)
//	--listen-client-urls     (etcd)
//	--advertise-client-urls  (etcd)
//	--initial-advertise-peer-urls and --listen-peer-urls are intentionally
//	excluded — these are the peer/quorum channel, not the client API.
func parseEtcdEndpointsFromArgs(tokens []string) []string {
	wanted := map[string]bool{
		"--etcd-servers":          true,
		"--listen-client-urls":    true,
		"--advertise-client-urls": true,
	}
	var out []string
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		lower := strings.ToLower(t)
		// Equals form: --flag=v1,v2
		if eq := strings.IndexByte(t, '='); eq != -1 {
			if wanted[strings.ToLower(t[:eq])] {
				out = append(out, splitCSV(t[eq+1:])...)
				continue
			}
		}
		// Two-token form: --flag v1,v2
		if wanted[lower] && i+1 < len(tokens) {
			out = append(out, splitCSV(tokens[i+1])...)
			i++
		}
	}
	return out
}

// splitCSV splits a comma-separated string and trims whitespace; empty
// fields are dropped.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalizeEtcdURL canonicalises a discovered URL into "scheme://host:port"
// form. If the input has no scheme, defaultScheme is assumed. If the host
// part lacks a port, ":2379" is appended (etcd's well-known client port).
// Returns "" if the input can't be parsed into a usable form.
func normalizeEtcdURL(raw, defaultScheme string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	scheme := defaultScheme
	if scheme == "" {
		scheme = "https"
	}
	// Strip any trailing path/slashes — etcd endpoints are bare host:port.
	if idx := strings.Index(s, "://"); idx != -1 {
		scheme = strings.ToLower(s[:idx])
		s = s[idx+3:]
	}
	// Cut after the first '/'.
	if slash := strings.IndexByte(s, '/'); slash != -1 {
		s = s[:slash]
	}
	if s == "" {
		return ""
	}
	if !strings.ContainsRune(s, ':') || isBracketedIPv6WithoutPort(s) {
		s += ":2379"
	}
	return scheme + "://" + s
}

// isBracketedIPv6WithoutPort returns true when s is "[…]" with no trailing
// ":port". "[::1]" → true; "[::1]:2379" → false; "10.0.0.1:2379" → false.
func isBracketedIPv6WithoutPort(s string) bool {
	if !strings.HasPrefix(s, "[") {
		return false
	}
	end := strings.LastIndexByte(s, ']')
	return end == len(s)-1
}

// dedupeEndpoints removes URL duplicates from in while preserving the first
// occurrence's order and source attribution.
func dedupeEndpoints(in []k8sEtcdEndpoint) []k8sEtcdEndpoint {
	seen := make(map[string]bool, len(in))
	var out []k8sEtcdEndpoint
	for _, e := range in {
		if e.URL == "" || seen[e.URL] {
			continue
		}
		seen[e.URL] = true
		out = append(out, e)
	}
	return out
}

// classifyEtcdProbe converts the raw HTTP outcome of an etcd probe into a
// structured result. The classification keys off:
//   - HTTP 200 with a parseable {"etcdserver":...} body → unauthenticated read
//   - HTTP 401/403                                       → auth required
//   - HTTP 400 with body mentioning client-cert/TLS      → TLS client cert needed
//   - TLS handshake error                                → tls-required
//   - dial / connect error                               → unreachable
//   - anything else                                      → error
//
// httpErr is the network/TLS error returned by the HTTP client (nil on success).
// httpStatus is the response code (0 if httpErr non-nil). body is the response
// body (already read; may be empty).
func classifyEtcdProbe(url string, httpStatus int, body []byte, httpErr error) k8sEtcdProbeResult {
	r := k8sEtcdProbeResult{URL: url, HTTPStatus: httpStatus}
	if httpErr != nil {
		msg := httpErr.Error()
		lower := strings.ToLower(msg)
		switch {
		case strings.Contains(lower, "tls"),
			strings.Contains(lower, "x509"),
			strings.Contains(lower, "certificate"),
			strings.Contains(lower, "handshake"):
			r.Status = "tls-required"
			r.Detail = msg
		case strings.Contains(lower, "connection refused"),
			strings.Contains(lower, "no route to host"),
			strings.Contains(lower, "i/o timeout"),
			strings.Contains(lower, "timeout"),
			strings.Contains(lower, "deadline exceeded"):
			r.Status = "unreachable"
			r.Detail = msg
		default:
			r.Status = "error"
			r.Detail = msg
		}
		return r
	}
	switch {
	case httpStatus == 200:
		if v, err := parseEtcdVersionResponse(body); err == nil && v.Server != "" {
			r.Status = "unauth"
			r.EtcdServer = v.Server
			r.EtcdCluster = v.Cluster
			r.UnauthAccess = true
			r.Detail = fmt.Sprintf("etcdserver=%s cluster=%s", v.Server, v.Cluster)
			return r
		}
		// 200 with a non-version body (e.g. /v2/keys/ root listing) is
		// still unauthenticated read access.
		r.Status = "unauth"
		r.UnauthAccess = true
		r.Detail = truncateBody(body, 80)
	case httpStatus == 401 || httpStatus == 403:
		r.Status = "auth-required"
		r.Detail = fmt.Sprintf("HTTP %d", httpStatus)
	case httpStatus == 400:
		bodyLower := strings.ToLower(string(body))
		if strings.Contains(bodyLower, "client certificate") || strings.Contains(bodyLower, "client cert") || strings.Contains(bodyLower, "tls handshake") {
			r.Status = "tls-required"
			r.Detail = "HTTP 400 client-cert required"
		} else {
			r.Status = "error"
			r.Detail = "HTTP 400"
		}
	default:
		r.Status = "error"
		r.Detail = fmt.Sprintf("HTTP %d", httpStatus)
	}
	return r
}

// k8sEtcdVersion is the JSON shape returned by GET /version on etcd v3.
type k8sEtcdVersion struct {
	Server  string `json:"etcdserver"`
	Cluster string `json:"etcdcluster"`
}

// parseEtcdVersionResponse decodes a /version response body. Returns an
// error if body is empty or not valid JSON with at least an etcdserver field.
func parseEtcdVersionResponse(body []byte) (k8sEtcdVersion, error) {
	var v k8sEtcdVersion
	if len(body) == 0 {
		return v, fmt.Errorf("empty body")
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return v, err
	}
	if v.Server == "" {
		return v, fmt.Errorf("missing etcdserver field")
	}
	return v, nil
}

// truncateBody returns at most n bytes of body as a single-line string,
// with newlines collapsed to spaces. Used in result details to avoid
// blowing out the operator console with HTML error pages.
func truncateBody(body []byte, n int) string {
	s := strings.TrimSpace(string(body))
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
