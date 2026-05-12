package commands

import (
	"strings"
	"testing"
)

// --- rbacRuleIsDangerous ---

func TestRBACRuleIsDangerous_FullWildcard(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"*"}, Resources: []string{"*"}})
	if !ok {
		t.Fatalf("rule */* should be dangerous")
	}
	if !strings.Contains(reason, "cluster-admin equivalent") {
		t.Errorf("reason = %q, want cluster-admin equivalent", reason)
	}
}

func TestRBACRuleIsDangerous_VerbWildcardSpecificResource(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"*"}, Resources: []string{"secrets"}})
	if !ok {
		t.Fatalf("*/secrets should be dangerous")
	}
	if !strings.Contains(reason, "all verbs on secrets") {
		t.Errorf("reason = %q", reason)
	}
}

func TestRBACRuleIsDangerous_ResourceWildcardCreate(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"create"}, Resources: []string{"*"}})
	if !ok {
		t.Fatalf("create on * should be dangerous")
	}
	if !strings.Contains(reason, "every resource") {
		t.Errorf("reason = %q", reason)
	}
}

func TestRBACRuleIsDangerous_ResourceWildcardSafeVerb(t *testing.T) {
	// "get" on * is information-disclosure-heavy but is not flagged as a
	// privesc path by the current heuristic. This documents that boundary.
	ok, _ := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"get"}, Resources: []string{"*"}})
	if ok {
		t.Errorf("get on * should NOT be flagged as privesc (information disclosure only)")
	}
}

func TestRBACRuleIsDangerous_SecretsGet(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"get", "list"}, Resources: []string{"secrets"}})
	if !ok {
		t.Fatalf("get secrets should be dangerous")
	}
	if !strings.Contains(reason, "read every secret") {
		t.Errorf("reason = %q", reason)
	}
}

func TestRBACRuleIsDangerous_PodsCreate(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"create"}, Resources: []string{"pods"}})
	if !ok {
		t.Fatalf("create pods should be dangerous")
	}
	if !strings.Contains(reason, "pods") {
		t.Errorf("reason should mention pods, got %q", reason)
	}
}

func TestRBACRuleIsDangerous_PodsExec(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"create"}, Resources: []string{"pods/exec"}})
	if !ok {
		t.Fatalf("create pods/exec should be dangerous")
	}
	if !strings.Contains(reason, "exec into") {
		t.Errorf("reason = %q", reason)
	}
}

func TestRBACRuleIsDangerous_Escalate(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"escalate"}, Resources: []string{"clusterroles"}})
	if !ok {
		t.Fatalf("escalate clusterroles should be dangerous")
	}
	if !strings.Contains(reason, "escalate") {
		t.Errorf("reason = %q", reason)
	}
}

func TestRBACRuleIsDangerous_Impersonate(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"impersonate"}, Resources: []string{"serviceaccounts"}})
	if !ok {
		t.Fatalf("impersonate serviceaccounts should be dangerous")
	}
	if !strings.Contains(reason, "impersonate") {
		t.Errorf("reason = %q", reason)
	}
}

func TestRBACRuleIsDangerous_TokenMint(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"create"}, Resources: []string{"serviceaccounts/token"}})
	if !ok {
		t.Fatalf("create serviceaccounts/token should be dangerous")
	}
	if !strings.Contains(reason, "mint tokens") {
		t.Errorf("reason = %q", reason)
	}
}

func TestRBACRuleIsDangerous_NodeProxy(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"create"}, Resources: []string{"nodes/proxy"}})
	if !ok {
		t.Fatalf("create nodes/proxy should be dangerous")
	}
	if !strings.Contains(reason, "kubelet API") {
		t.Errorf("reason = %q", reason)
	}
}

func TestRBACRuleIsDangerous_ConfigMapsRead(t *testing.T) {
	// Reading configmaps is interesting but not flagged as privesc by itself.
	ok, _ := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"get", "list"}, Resources: []string{"configmaps"}})
	if ok {
		t.Errorf("get configmaps should not be flagged (data exposure only)")
	}
}

func TestRBACRuleIsDangerous_EmptyRule(t *testing.T) {
	ok, _ := rbacRuleIsDangerous(k8sRBACRule{})
	if ok {
		t.Errorf("empty rule should not be dangerous")
	}
}

func TestRBACRuleIsDangerous_CaseInsensitive(t *testing.T) {
	// Some API responses normalise to lower; some preserve casing.
	ok, _ := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"CREATE"}, Resources: []string{"PODS"}})
	if !ok {
		t.Errorf("CREATE/PODS (upper case) should be flagged")
	}
}

func TestRBACRuleIsDangerous_WebhookInstall(t *testing.T) {
	ok, reason := rbacRuleIsDangerous(k8sRBACRule{Verbs: []string{"create"}, Resources: []string{"mutatingwebhookconfigurations"}})
	if !ok {
		t.Fatalf("create mutatingwebhookconfigurations should be dangerous")
	}
	if !strings.Contains(reason, "mutating webhooks") {
		t.Errorf("reason = %q", reason)
	}
}

// --- bindingIsClusterAdmin ---

func TestBindingIsClusterAdmin_DirectRoleRef(t *testing.T) {
	b := k8sRBACBinding{
		Kind:    "ClusterRoleBinding",
		Name:    "test-binding",
		RoleRef: k8sRBACRoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []k8sRBACSubject{
			{Kind: "ServiceAccount", Name: "default", Namespace: "kube-system"},
		},
	}
	if !bindingIsClusterAdmin(b) {
		t.Errorf("binding referencing cluster-admin should match")
	}
}

func TestBindingIsClusterAdmin_SystemMastersGroup(t *testing.T) {
	b := k8sRBACBinding{
		Kind:    "ClusterRoleBinding",
		Name:    "masters-binding",
		RoleRef: k8sRBACRoleRef{Kind: "ClusterRole", Name: "view"},
		Subjects: []k8sRBACSubject{
			{Kind: "Group", Name: "system:masters"},
		},
	}
	if !bindingIsClusterAdmin(b) {
		t.Errorf("binding granting system:masters should match")
	}
}

func TestBindingIsClusterAdmin_NotClusterAdmin(t *testing.T) {
	b := k8sRBACBinding{
		Kind:     "ClusterRoleBinding",
		Name:     "viewer",
		RoleRef:  k8sRBACRoleRef{Kind: "ClusterRole", Name: "view"},
		Subjects: []k8sRBACSubject{{Kind: "User", Name: "alice"}},
	}
	if bindingIsClusterAdmin(b) {
		t.Errorf("view binding should not match cluster-admin")
	}
}

func TestBindingIsClusterAdmin_CaseInsensitive(t *testing.T) {
	b := k8sRBACBinding{
		Kind:    "ClusterRoleBinding",
		Name:    "ca",
		RoleRef: k8sRBACRoleRef{Kind: "CLUSTERROLE", Name: "Cluster-Admin"},
	}
	if !bindingIsClusterAdmin(b) {
		t.Errorf("case-insensitive cluster-admin check should match")
	}
}

// --- formatRBACSubject / formatRBACBinding ---

func TestFormatRBACSubject_Namespaced(t *testing.T) {
	s := k8sRBACSubject{Kind: "ServiceAccount", Name: "build-bot", Namespace: "ci"}
	got := formatRBACSubject(s)
	if got != "ServiceAccount/build-bot@ci" {
		t.Errorf("got %q", got)
	}
}

func TestFormatRBACSubject_Cluster(t *testing.T) {
	s := k8sRBACSubject{Kind: "User", Name: "admin@globetech.biz"}
	got := formatRBACSubject(s)
	if got != "User/admin@globetech.biz" {
		t.Errorf("got %q", got)
	}
}

func TestFormatRBACBinding_Namespaced(t *testing.T) {
	b := k8sRBACBinding{Kind: "RoleBinding", Name: "db-rw", Namespace: "prod"}
	got := formatRBACBinding(b)
	if got != "RoleBinding/db-rw@prod" {
		t.Errorf("got %q", got)
	}
}

// --- rbacRuleLookupKey ---

func TestRBACRuleLookupKey_ClusterRole(t *testing.T) {
	b := k8sRBACBinding{Kind: "ClusterRoleBinding", RoleRef: k8sRBACRoleRef{Kind: "ClusterRole", Name: "cluster-admin"}}
	if got := rbacRuleLookupKey(b); got != "cluster/cluster-admin" {
		t.Errorf("got %q", got)
	}
}

func TestRBACRuleLookupKey_NamespacedRole(t *testing.T) {
	b := k8sRBACBinding{Kind: "RoleBinding", Namespace: "ci", RoleRef: k8sRBACRoleRef{Kind: "Role", Name: "deployer"}}
	if got := rbacRuleLookupKey(b); got != "ci/deployer" {
		t.Errorf("got %q", got)
	}
}

func TestRBACRuleLookupKey_InvalidClusterRBToNamespacedRole(t *testing.T) {
	// A ClusterRoleBinding referencing a namespaced Role is invalid K8s but
	// the helper should still produce a sensible cluster-scoped key.
	b := k8sRBACBinding{Kind: "ClusterRoleBinding", RoleRef: k8sRBACRoleRef{Kind: "Role", Name: "weird"}}
	if got := rbacRuleLookupKey(b); got != "cluster/weird" {
		t.Errorf("got %q", got)
	}
}

// --- summarizeRBACPrivesc ---

func TestSummarizeRBACPrivesc_ClusterAdminBinding(t *testing.T) {
	bindings := []k8sRBACBinding{
		{
			Kind:     "ClusterRoleBinding",
			Name:     "ca-bind",
			RoleRef:  k8sRBACRoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []k8sRBACSubject{{Kind: "ServiceAccount", Name: "robot", Namespace: "kube-system"}},
		},
	}
	findings := summarizeRBACPrivesc(bindings, nil)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != "crit" {
		t.Errorf("severity = %q", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Reason, "cluster-admin") {
		t.Errorf("reason = %q", findings[0].Reason)
	}
}

func TestSummarizeRBACPrivesc_DangerousClusterRole(t *testing.T) {
	bindings := []k8sRBACBinding{
		{
			Kind:     "ClusterRoleBinding",
			Name:     "deployer-bind",
			RoleRef:  k8sRBACRoleRef{Kind: "ClusterRole", Name: "deployer"},
			Subjects: []k8sRBACSubject{{Kind: "ServiceAccount", Name: "ci-bot", Namespace: "ci"}},
		},
	}
	roleRules := map[string][]k8sRBACRule{
		"cluster/deployer": {
			{Verbs: []string{"create"}, Resources: []string{"pods"}},
			{Verbs: []string{"get"}, Resources: []string{"secrets"}},
		},
	}
	findings := summarizeRBACPrivesc(bindings, roleRules)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	// Both findings should be for the same subject.
	for _, f := range findings {
		if f.Subject != "ServiceAccount/ci-bot@ci" {
			t.Errorf("subject = %q", f.Subject)
		}
		if f.Binding != "ClusterRoleBinding/deployer-bind" {
			t.Errorf("binding = %q", f.Binding)
		}
	}
}

func TestSummarizeRBACPrivesc_NamespacedRoleBinding(t *testing.T) {
	bindings := []k8sRBACBinding{
		{
			Kind:      "RoleBinding",
			Name:      "ns-binding",
			Namespace: "prod",
			RoleRef:   k8sRBACRoleRef{Kind: "Role", Name: "secret-reader"},
			Subjects:  []k8sRBACSubject{{Kind: "User", Name: "alice"}},
		},
	}
	roleRules := map[string][]k8sRBACRule{
		"prod/secret-reader": {{Verbs: []string{"get", "list"}, Resources: []string{"secrets"}}},
	}
	findings := summarizeRBACPrivesc(bindings, roleRules)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Subject != "User/alice" {
		t.Errorf("subject = %q", findings[0].Subject)
	}
	if findings[0].Binding != "RoleBinding/ns-binding@prod" {
		t.Errorf("binding = %q", findings[0].Binding)
	}
}

func TestSummarizeRBACPrivesc_NoRulesAvailable(t *testing.T) {
	// Binding references a role we don't have rules for — should not crash.
	bindings := []k8sRBACBinding{
		{
			Kind:     "ClusterRoleBinding",
			Name:     "unknown",
			RoleRef:  k8sRBACRoleRef{Kind: "ClusterRole", Name: "mystery"},
			Subjects: []k8sRBACSubject{{Kind: "User", Name: "x"}},
		},
	}
	findings := summarizeRBACPrivesc(bindings, nil)
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 when rules unavailable", len(findings))
	}
}

func TestSummarizeRBACPrivesc_SortOrder(t *testing.T) {
	bindings := []k8sRBACBinding{
		// info severity (no rule = no flag, so we craft a warn + crit pair)
		{
			Kind:     "ClusterRoleBinding",
			Name:     "ci-bind",
			RoleRef:  k8sRBACRoleRef{Kind: "ClusterRole", Name: "ci-role"},
			Subjects: []k8sRBACSubject{{Kind: "ServiceAccount", Name: "bot", Namespace: "ci"}},
		},
		{
			Kind:     "ClusterRoleBinding",
			Name:     "admin-bind",
			RoleRef:  k8sRBACRoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []k8sRBACSubject{{Kind: "User", Name: "alice"}},
		},
	}
	roleRules := map[string][]k8sRBACRule{
		"cluster/ci-role": {{Verbs: []string{"create"}, Resources: []string{"pods"}}},
	}
	findings := summarizeRBACPrivesc(bindings, roleRules)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	if findings[0].Severity != "crit" {
		t.Errorf("first finding severity = %q, want crit", findings[0].Severity)
	}
	if findings[1].Severity != "warn" {
		t.Errorf("second finding severity = %q, want warn", findings[1].Severity)
	}
}

// --- Node helpers ---

func TestFormatNodeTaint_WithValue(t *testing.T) {
	got := formatNodeTaint(k8sNodeTaint{Key: "dedicated", Value: "gpu", Effect: "NoSchedule"})
	if got != "dedicated=gpu:NoSchedule" {
		t.Errorf("got %q", got)
	}
}

func TestFormatNodeTaint_NoValue(t *testing.T) {
	got := formatNodeTaint(k8sNodeTaint{Key: "node-role.kubernetes.io/control-plane", Effect: "NoSchedule"})
	if got != "node-role.kubernetes.io/control-plane:NoSchedule" {
		t.Errorf("got %q", got)
	}
}

func TestExtractNodeRoles_ControlPlane(t *testing.T) {
	labels := map[string]string{
		"node-role.kubernetes.io/control-plane": "",
		"node-role.kubernetes.io/master":        "",
		"kubernetes.io/hostname":                "node-01",
	}
	roles := extractNodeRoles(labels)
	if len(roles) != 2 {
		t.Fatalf("got %d roles, want 2", len(roles))
	}
	if roles[0] != "control-plane" || roles[1] != "master" {
		t.Errorf("roles = %v", roles)
	}
}

func TestExtractNodeRoles_None(t *testing.T) {
	labels := map[string]string{"kubernetes.io/hostname": "worker-01"}
	roles := extractNodeRoles(labels)
	if len(roles) != 0 {
		t.Errorf("got %d roles, want 0", len(roles))
	}
}

func TestPickAddressByType_InternalIP(t *testing.T) {
	addrs := []k8sNodeAddress{
		{Type: "Hostname", Address: "node-01"},
		{Type: "InternalIP", Address: "10.0.0.1"},
		{Type: "ExternalIP", Address: "203.0.113.5"},
	}
	if got := pickAddressByType(addrs, "InternalIP"); got != "10.0.0.1" {
		t.Errorf("got %q", got)
	}
	if got := pickAddressByType(addrs, "ExternalIP"); got != "203.0.113.5" {
		t.Errorf("got %q", got)
	}
	if got := pickAddressByType(addrs, "Hostname"); got != "node-01" {
		t.Errorf("got %q", got)
	}
}

func TestPickAddressByType_Missing(t *testing.T) {
	addrs := []k8sNodeAddress{{Type: "InternalIP", Address: "10.0.0.1"}}
	if got := pickAddressByType(addrs, "ExternalIP"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestPickAddressByType_CaseInsensitive(t *testing.T) {
	addrs := []k8sNodeAddress{{Type: "internalip", Address: "10.0.0.1"}}
	if got := pickAddressByType(addrs, "InternalIP"); got != "10.0.0.1" {
		t.Errorf("got %q", got)
	}
}

func TestNodeReadyCondition_True(t *testing.T) {
	cond := []map[string]any{
		{"type": "MemoryPressure", "status": "False"},
		{"type": "Ready", "status": "True"},
	}
	if got := nodeReadyCondition(cond); got != "True" {
		t.Errorf("got %q", got)
	}
}

func TestNodeReadyCondition_Missing(t *testing.T) {
	cond := []map[string]any{{"type": "DiskPressure", "status": "False"}}
	if got := nodeReadyCondition(cond); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestNodeReadyCondition_LowercaseType(t *testing.T) {
	cond := []map[string]any{{"type": "ready", "status": "Unknown"}}
	if got := nodeReadyCondition(cond); got != "Unknown" {
		t.Errorf("got %q", got)
	}
}

// --- rbacSeverityFor ---

func TestRBACSeverityFor_Crit(t *testing.T) {
	cases := []string{
		"cluster-admin equivalent: rule grants all verbs on all resources",
		"all verbs on secrets (resource wildcard verbs)",
		"escalate or bind cluster-roles (grant cluster-admin to yourself)",
		"impersonate any service account (token-free identity bypass)",
		"mint tokens for any service account (no-rotation credential theft)",
		"create on every resource (resource wildcard)",
	}
	for _, c := range cases {
		if rbacSeverityFor(c) != "crit" {
			t.Errorf("rbacSeverityFor(%q) = %q, want crit", c, rbacSeverityFor(c))
		}
	}
}

func TestRBACSeverityFor_Warn(t *testing.T) {
	cases := []string{
		"create/modify pods (run arbitrary containers, optionally privileged or hostPath-mounted)",
		"read every secret in scope (service-account tokens, registry creds, app secrets)",
		"install admission webhooks (intercept and modify any API call)",
		"exec into any pod in scope (root-equivalent if pod is privileged)",
	}
	for _, c := range cases {
		if rbacSeverityFor(c) != "warn" {
			t.Errorf("rbacSeverityFor(%q) = %q, want warn", c, rbacSeverityFor(c))
		}
	}
}
