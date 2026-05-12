//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

// escapeK8sRBAC enumerates ClusterRoles, Roles, and their bindings via the
// K8s API, then cross-references binding subjects against the rule sets to
// surface privilege-escalation paths.
//
// Scope behaviour:
//   - With no -path argument: enumerates cluster-scoped objects (ClusterRoles
//     and ClusterRoleBindings).
//   - With -path <namespace>: in addition to cluster-scoped objects, also
//     enumerates that namespace's Roles and RoleBindings.
//   - With -path "*" : tries every reachable namespace (best-effort; uses
//     /api/v1/namespaces first, falls back to current namespace on 403).
//
// Detection: bindings referencing cluster-admin or system:masters are flagged
// crit. Bindings to any other role are joined to the role's rule list and
// each rule is checked via rbacRuleIsDangerous; severity is computed by
// rbacSeverityFor.
func escapeK8sRBAC(args containerEscapeArgs) (string, string) {
	kc, err := newK8sClient()
	if err != nil {
		return fmt.Sprintf("K8s RBAC enumeration failed: %v", err), "error"
	}
	defer structs.ZeroString(&kc.token)

	var sb strings.Builder
	sb.WriteString("=== KUBERNETES RBAC ENUMERATION ===\n\n")
	sb.WriteString(fmt.Sprintf("API Server: %s\n", kc.apiServer))
	sb.WriteString(fmt.Sprintf("Current SA Namespace: %s\n\n", kc.namespace))

	// 1. Cluster-scoped: ClusterRoles + ClusterRoleBindings.
	clusterRules, clusterRuleErrs := fetchClusterRoles(kc)
	clusterBindings, clusterBindErrs := fetchClusterRoleBindings(kc)

	// 2. Namespaced: discover the namespace set, then fetch Roles +
	//    RoleBindings per namespace.
	nsList := resolveRBACNamespaces(kc, args.Path)
	roleRules := clusterRules
	var bindings []k8sRBACBinding
	bindings = append(bindings, clusterBindings...)

	for _, ns := range nsList {
		nsRules, ruleErr := fetchNamespacedRoles(kc, ns)
		for k, v := range nsRules {
			roleRules[k] = v
		}
		nsBindings, bindErr := fetchNamespacedRoleBindings(kc, ns)
		bindings = append(bindings, nsBindings...)

		if ruleErr != "" {
			sb.WriteString(fmt.Sprintf("[!] roles in %s: %s\n", ns, ruleErr))
		}
		if bindErr != "" {
			sb.WriteString(fmt.Sprintf("[!] rolebindings in %s: %s\n", ns, bindErr))
		}
	}

	if clusterRuleErrs != "" {
		sb.WriteString(fmt.Sprintf("[!] clusterroles: %s\n", clusterRuleErrs))
	}
	if clusterBindErrs != "" {
		sb.WriteString(fmt.Sprintf("[!] clusterrolebindings: %s\n", clusterBindErrs))
	}

	sb.WriteString(fmt.Sprintf("\n--- Counts ---\n"))
	sb.WriteString(fmt.Sprintf("  ClusterRoles loaded:        %d\n", countKeysWithPrefix(roleRules, "cluster/")))
	sb.WriteString(fmt.Sprintf("  Namespaced Roles loaded:    %d\n", len(roleRules)-countKeysWithPrefix(roleRules, "cluster/")))
	sb.WriteString(fmt.Sprintf("  Bindings analysed:          %d\n", len(bindings)))

	// 3. Privesc analysis.
	findings := summarizeRBACPrivesc(bindings, roleRules)
	sb.WriteString(fmt.Sprintf("\n--- Privilege Escalation Findings (%d) ---\n", len(findings)))
	if len(findings) == 0 {
		sb.WriteString("  None detected. RBAC posture looks reasonable for the scoped namespaces.\n")
	}
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("  [%s] %s\n", strings.ToUpper(f.Severity), f.Subject))
		sb.WriteString(fmt.Sprintf("        via %s → %s\n", f.Binding, f.Role))
		sb.WriteString(fmt.Sprintf("        %s\n", f.Reason))
	}

	// 4. Self-check: SelfSubjectRulesReview to surface what THIS callback can do.
	if review := fetchSelfSubjectRulesReview(kc, kc.namespace); review != "" {
		sb.WriteString(fmt.Sprintf("\n--- Effective Permissions for current SA in %s ---\n", kc.namespace))
		sb.WriteString(review)
	}

	return sb.String(), "success"
}

// fetchClusterRoles loads /apis/rbac.authorization.k8s.io/v1/clusterroles
// and returns rules keyed "cluster/<rolename>".
func fetchClusterRoles(kc *k8sClient) (map[string][]k8sRBACRule, string) {
	out := make(map[string][]k8sRBACRule)
	data, code, err := kc.k8sGet("/apis/rbac.authorization.k8s.io/v1/clusterroles")
	if err != nil {
		return out, err.Error()
	}
	defer structs.ZeroBytes(data)
	if code != 200 {
		return out, fmt.Sprintf("HTTP %d", code)
	}

	var resp struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Rules []k8sRBACRule `json:"rules"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return out, err.Error()
	}
	for _, item := range resp.Items {
		out["cluster/"+item.Metadata.Name] = item.Rules
	}
	return out, ""
}

// fetchClusterRoleBindings loads
// /apis/rbac.authorization.k8s.io/v1/clusterrolebindings.
func fetchClusterRoleBindings(kc *k8sClient) ([]k8sRBACBinding, string) {
	var out []k8sRBACBinding
	data, code, err := kc.k8sGet("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
	if err != nil {
		return out, err.Error()
	}
	defer structs.ZeroBytes(data)
	if code != 200 {
		return out, fmt.Sprintf("HTTP %d", code)
	}

	var resp struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Subjects []k8sRBACSubject `json:"subjects"`
			RoleRef  k8sRBACRoleRef   `json:"roleRef"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return out, err.Error()
	}
	for _, item := range resp.Items {
		out = append(out, k8sRBACBinding{
			Kind:         "ClusterRoleBinding",
			Name:         item.Metadata.Name,
			ClusterScope: true,
			Subjects:     item.Subjects,
			RoleRef:      item.RoleRef,
		})
	}
	return out, ""
}

// fetchNamespacedRoles loads Roles for a single namespace and returns rules
// keyed "<namespace>/<rolename>".
func fetchNamespacedRoles(kc *k8sClient, ns string) (map[string][]k8sRBACRule, string) {
	out := make(map[string][]k8sRBACRule)
	path := fmt.Sprintf("/apis/rbac.authorization.k8s.io/v1/namespaces/%s/roles", ns)
	data, code, err := kc.k8sGet(path)
	if err != nil {
		return out, err.Error()
	}
	defer structs.ZeroBytes(data)
	if code != 200 {
		return out, fmt.Sprintf("HTTP %d", code)
	}

	var resp struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Rules []k8sRBACRule `json:"rules"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return out, err.Error()
	}
	for _, item := range resp.Items {
		out[ns+"/"+item.Metadata.Name] = item.Rules
	}
	return out, ""
}

// fetchNamespacedRoleBindings loads RoleBindings for a single namespace.
func fetchNamespacedRoleBindings(kc *k8sClient, ns string) ([]k8sRBACBinding, string) {
	var out []k8sRBACBinding
	path := fmt.Sprintf("/apis/rbac.authorization.k8s.io/v1/namespaces/%s/rolebindings", ns)
	data, code, err := kc.k8sGet(path)
	if err != nil {
		return out, err.Error()
	}
	defer structs.ZeroBytes(data)
	if code != 200 {
		return out, fmt.Sprintf("HTTP %d", code)
	}

	var resp struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Subjects []k8sRBACSubject `json:"subjects"`
			RoleRef  k8sRBACRoleRef   `json:"roleRef"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return out, err.Error()
	}
	for _, item := range resp.Items {
		nsName := item.Metadata.Namespace
		if nsName == "" {
			nsName = ns
		}
		// A namespaced RoleBinding can reference a ClusterRole; track that
		// so the lookup-key helper finds the correct rules.
		clusterScope := strings.EqualFold(item.RoleRef.Kind, "ClusterRole")
		out = append(out, k8sRBACBinding{
			Kind:         "RoleBinding",
			Name:         item.Metadata.Name,
			Namespace:    nsName,
			ClusterScope: clusterScope,
			Subjects:     item.Subjects,
			RoleRef:      item.RoleRef,
		})
	}
	return out, ""
}

// resolveRBACNamespaces returns the namespaces to enumerate Roles +
// RoleBindings against. pathArg semantics:
//   - empty   → just the current SA namespace
//   - "*"     → every namespace listed via /api/v1/namespaces (best-effort)
//   - "a,b,c" → those literal namespaces
func resolveRBACNamespaces(kc *k8sClient, pathArg string) []string {
	pathArg = strings.TrimSpace(pathArg)
	if pathArg == "" {
		return []string{kc.namespace}
	}
	if pathArg != "*" {
		var out []string
		for _, n := range strings.Split(pathArg, ",") {
			if n = strings.TrimSpace(n); n != "" {
				out = append(out, n)
			}
		}
		return out
	}

	data, code, err := kc.k8sGet("/api/v1/namespaces")
	if err != nil || code != 200 {
		return []string{kc.namespace}
	}
	defer structs.ZeroBytes(data)

	var resp struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return []string{kc.namespace}
	}
	var out []string
	for _, n := range resp.Items {
		out = append(out, n.Metadata.Name)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return []string{kc.namespace}
	}
	return out
}

// fetchSelfSubjectRulesReview asks the API server what verbs/resources the
// caller can perform in `ns`. Returns a multi-line formatted view; empty
// string on error (the upstream caller treats that as "skip").
func fetchSelfSubjectRulesReview(kc *k8sClient, ns string) string {
	body := []byte(fmt.Sprintf(`{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"%s"}}`, ns))
	data, code, err := kc.k8sPost("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", body)
	if err != nil {
		return ""
	}
	defer structs.ZeroBytes(data)
	if code < 200 || code >= 300 {
		return ""
	}

	var resp struct {
		Status struct {
			ResourceRules    []k8sRBACRule `json:"resourceRules"`
			NonResourceRules []struct {
				Verbs           []string `json:"verbs"`
				NonResourceURLs []string `json:"nonResourceURLs"`
			} `json:"nonResourceRules"`
			Incomplete bool `json:"incomplete"`
		} `json:"status"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return ""
	}

	var sb strings.Builder
	for _, r := range resp.Status.ResourceRules {
		if ok, reason := rbacRuleIsDangerous(r); ok {
			sb.WriteString(fmt.Sprintf("  [!] %s on %s — %s\n",
				strings.Join(r.Verbs, ","), strings.Join(r.Resources, ","), reason))
		} else {
			sb.WriteString(fmt.Sprintf("  [-] %s on %s\n",
				strings.Join(r.Verbs, ","), strings.Join(r.Resources, ",")))
		}
	}
	if resp.Status.Incomplete {
		sb.WriteString("  (incomplete — review truncated by server)\n")
	}
	return sb.String()
}

// countKeysWithPrefix returns the number of keys in m that start with prefix.
func countKeysWithPrefix(m map[string][]k8sRBACRule, prefix string) int {
	n := 0
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}
