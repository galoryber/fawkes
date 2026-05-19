package commands

// RBAC privilege escalation analysis helpers for K8s container escape.
// Used by container_escape_k8s_rbac.go.

import (
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
// a namespaced RoleBinding.
type k8sRBACBinding struct {
	Kind         string
	Name         string
	Namespace    string
	ClusterScope bool
	Subjects     []k8sRBACSubject
	RoleRef      k8sRBACRoleRef
}

// k8sRBACFinding is one detected privilege-escalation path or risky grant.
type k8sRBACFinding struct {
	Severity string
	Subject  string
	Binding  string
	Role     string
	Reason   string
}

// dangerousResourceVerbs maps (resource -> set of verbs) to a human reason
// explaining the escalation path.
var dangerousResourceVerbs = []struct {
	Resource string
	Verbs    []string
	Reason   string
}{
	{"pods/exec", []string{"create", "get"}, "exec into any pod in scope (root-equivalent if pod is privileged)"},
	{"pods/attach", []string{"create", "get"}, "attach to any pod's TTY (interactive shell capture)"},
	{"pods/portforward", []string{"create", "get"}, "port-forward to any pod (data-plane MITM)"},
	{"pods/proxy", []string{"create", "get"}, "proxy traffic via any pod"},
	{"pods", []string{"create", "update", "patch"}, "create/modify pods (run arbitrary containers, optionally privileged or hostPath-mounted)"},
	{"deployments", []string{"create", "update", "patch"}, "create/modify deployments (indirect pod creation)"},
	{"daemonsets", []string{"create", "update", "patch"}, "create/modify daemonsets (per-node pod placement = host compromise)"},
	{"statefulsets", []string{"create", "update", "patch"}, "create/modify statefulsets (persistent storage + identity attack surface)"},
	{"jobs", []string{"create", "update", "patch"}, "create/modify jobs (one-shot container exec)"},
	{"cronjobs", []string{"create", "update", "patch"}, "create/modify cronjobs (scheduled persistence)"},
	{"secrets", []string{"get", "list", "watch"}, "read every secret in scope (service-account tokens, registry creds, app secrets)"},
	{"serviceaccounts", []string{"impersonate"}, "impersonate any service account (token-free identity bypass)"},
	{"serviceaccounts/token", []string{"create"}, "mint tokens for any service account (no-rotation credential theft)"},
	{"nodes", []string{"update", "patch", "create", "delete"}, "modify nodes (taints, labels, scheduling) — full cluster control"},
	{"nodes/proxy", []string{"create", "get"}, "proxy through kubelet API (run pods, read logs without RBAC)"},
	{"roles", []string{"escalate", "bind"}, "escalate or bind roles (grant yourself arbitrary verbs)"},
	{"clusterroles", []string{"escalate", "bind"}, "escalate or bind cluster-roles (grant cluster-admin to yourself)"},
	{"rolebindings", []string{"create", "update", "patch"}, "create/modify rolebindings (grant any role to any subject)"},
	{"clusterrolebindings", []string{"create", "update", "patch"}, "create/modify cluster-rolebindings (cluster-admin self-grant)"},
	{"certificatesigningrequests/approval", []string{"create", "update"}, "auto-approve CSRs (mint kubelet certs for arbitrary nodes)"},
	{"validatingwebhookconfigurations", []string{"create", "update", "patch"}, "install admission webhooks (intercept and modify any API call)"},
	{"mutatingwebhookconfigurations", []string{"create", "update", "patch"}, "install mutating webhooks (rewrite pod specs cluster-wide)"},
}

// rbacRuleIsDangerous returns (true, reason) if the rule grants an
// escalation-class permission.
func rbacRuleIsDangerous(rule k8sRBACRule) (bool, string) {
	verbs := lowerSet(rule.Verbs)
	resources := lowerSet(rule.Resources)

	hasVerbWildcard := verbs["*"]
	hasResourceWildcard := resources["*"]

	if hasVerbWildcard && hasResourceWildcard {
		return true, "cluster-admin equivalent: rule grants all verbs on all resources"
	}
	if hasVerbWildcard {
		for res := range resources {
			if res == "" {
				continue
			}
			return true, fmt.Sprintf("all verbs on %s (resource wildcard verbs)", res)
		}
	}
	if hasResourceWildcard {
		for v := range verbs {
			switch v {
			case "create", "update", "patch", "delete", "deletecollection", "impersonate", "escalate", "bind":
				return true, fmt.Sprintf("%s on every resource (resource wildcard)", v)
			}
		}
	}

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

// formatRBACSubject renders a subject as "Kind/Name[@namespace]".
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
// subject/binding pair.
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

// rbacRuleLookupKey returns the map key for looking up rules for a binding's
// referenced role.
func rbacRuleLookupKey(b k8sRBACBinding) string {
	if strings.EqualFold(b.RoleRef.Kind, "ClusterRole") {
		return "cluster/" + b.RoleRef.Name
	}
	if b.Namespace == "" {
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
