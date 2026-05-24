package commands

// Node summary types and helpers for K8s container escape.
// Used by container_escape_k8s_nodes.go.

import (
	"fmt"
	"sort"
	"strings"
)

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

// k8sNodeSummary is the flat summary that escapeK8sNodes presents.
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

// formatNodeTaint renders one taint as "key=value:effect".
func formatNodeTaint(t k8sNodeTaint) string {
	if t.Value == "" {
		return fmt.Sprintf("%s:%s", t.Key, t.Effect)
	}
	return fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect)
}

// extractNodeRoles pulls role names out of node labels.
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

// pickAddressByType returns the first address matching the given type.
func pickAddressByType(addrs []k8sNodeAddress, typ string) string {
	for _, a := range addrs {
		if strings.EqualFold(a.Type, typ) {
			return a.Address
		}
	}
	return ""
}

// nodeReadyCondition returns "True"/"False"/"Unknown" or "" if the Ready
// condition isn't present.
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
