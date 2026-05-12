//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// escapeK8sNodes enumerates cluster nodes via /api/v1/nodes and surfaces
// the attack-surface-relevant fields: kubelet version + OS image + kernel
// (vulnerable kernel hunt), pod CIDRs (network reach), taints + roles
// (which nodes run control-plane workloads vs general workers),
// internal/external IPs (lateral movement targets), allocatable resources
// (where to deploy a workload).
func escapeK8sNodes(args containerEscapeArgs) (string, string) {
	_ = args // node enumeration is cluster-scoped — args are unused for now
	kc, err := newK8sClient()
	if err != nil {
		return fmt.Sprintf("K8s node enumeration failed: %v", err), "error"
	}
	defer structs.ZeroString(&kc.token)

	data, code, err := kc.k8sGet("/api/v1/nodes")
	if err != nil {
		return fmt.Sprintf("GET /api/v1/nodes failed: %v", err), "error"
	}
	defer structs.ZeroBytes(data)
	if code != 200 {
		return fmt.Sprintf("Access denied listing nodes (HTTP %d)", code), "error"
	}

	var resp struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				PodCIDR  string         `json:"podCIDR"`
				PodCIDRs []string       `json:"podCIDRs"`
				Taints   []k8sNodeTaint `json:"taints"`
			} `json:"spec"`
			Status struct {
				NodeInfo struct {
					KubeletVersion          string `json:"kubeletVersion"`
					OSImage                 string `json:"osImage"`
					KernelVersion           string `json:"kernelVersion"`
					ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
					Architecture            string `json:"architecture"`
				} `json:"nodeInfo"`
				Addresses   []k8sNodeAddress `json:"addresses"`
				Allocatable struct {
					CPU    string `json:"cpu"`
					Memory string `json:"memory"`
					Pods   string `json:"pods"`
				} `json:"allocatable"`
				Conditions []map[string]any `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Sprintf("Failed to parse nodes response: %v", err), "error"
	}

	var sb strings.Builder
	sb.WriteString("=== KUBERNETES NODE ENUMERATION ===\n\n")
	sb.WriteString(fmt.Sprintf("API Server: %s\n", kc.apiServer))
	sb.WriteString(fmt.Sprintf("Nodes:      %d\n\n", len(resp.Items)))

	for _, n := range resp.Items {
		summary := k8sNodeSummary{
			Name:              n.Metadata.Name,
			Roles:             extractNodeRoles(n.Metadata.Labels),
			InternalIP:        pickAddressByType(n.Status.Addresses, "InternalIP"),
			ExternalIP:        pickAddressByType(n.Status.Addresses, "ExternalIP"),
			Hostname:          pickAddressByType(n.Status.Addresses, "Hostname"),
			PodCIDR:           n.Spec.PodCIDR,
			KubeletVersion:    n.Status.NodeInfo.KubeletVersion,
			OSImage:           n.Status.NodeInfo.OSImage,
			KernelVersion:     n.Status.NodeInfo.KernelVersion,
			ContainerRuntime:  n.Status.NodeInfo.ContainerRuntimeVersion,
			AllocatableCPU:    n.Status.Allocatable.CPU,
			AllocatableMemory: n.Status.Allocatable.Memory,
			Ready:             nodeReadyCondition(n.Status.Conditions),
		}
		for _, t := range n.Spec.Taints {
			summary.Taints = append(summary.Taints, formatNodeTaint(t))
		}

		sb.WriteString(fmt.Sprintf("[*] %s\n", summary.Name))
		if len(summary.Roles) > 0 {
			sb.WriteString(fmt.Sprintf("    Roles:        %s\n", strings.Join(summary.Roles, ",")))
		}
		sb.WriteString(fmt.Sprintf("    Ready:        %s\n", emptyToDash(summary.Ready)))
		if summary.InternalIP != "" {
			sb.WriteString(fmt.Sprintf("    InternalIP:   %s\n", summary.InternalIP))
		}
		if summary.ExternalIP != "" {
			sb.WriteString(fmt.Sprintf("    ExternalIP:   %s\n", summary.ExternalIP))
		}
		if summary.Hostname != "" {
			sb.WriteString(fmt.Sprintf("    Hostname:     %s\n", summary.Hostname))
		}
		if summary.PodCIDR != "" {
			sb.WriteString(fmt.Sprintf("    PodCIDR:      %s\n", summary.PodCIDR))
		}
		if len(n.Spec.PodCIDRs) > 1 {
			sb.WriteString(fmt.Sprintf("    PodCIDRs:     %s\n", strings.Join(n.Spec.PodCIDRs, ",")))
		}
		sb.WriteString(fmt.Sprintf("    Kubelet:      %s\n", emptyToDash(summary.KubeletVersion)))
		sb.WriteString(fmt.Sprintf("    OS:           %s\n", emptyToDash(summary.OSImage)))
		sb.WriteString(fmt.Sprintf("    Kernel:       %s\n", emptyToDash(summary.KernelVersion)))
		sb.WriteString(fmt.Sprintf("    Runtime:      %s\n", emptyToDash(summary.ContainerRuntime)))
		sb.WriteString(fmt.Sprintf("    Arch:         %s\n", emptyToDash(n.Status.NodeInfo.Architecture)))
		if summary.AllocatableCPU != "" || summary.AllocatableMemory != "" {
			sb.WriteString(fmt.Sprintf("    Allocatable:  cpu=%s mem=%s pods=%s\n",
				emptyToDash(summary.AllocatableCPU),
				emptyToDash(summary.AllocatableMemory),
				emptyToDash(n.Status.Allocatable.Pods)))
		}
		if len(summary.Taints) > 0 {
			sb.WriteString(fmt.Sprintf("    Taints:       %s\n", strings.Join(summary.Taints, " | ")))
		}
		sb.WriteString("\n")
	}

	return sb.String(), "success"
}

// emptyToDash returns "—" if s is empty; otherwise s. Keeps the human output
// columns lined up when fields are missing.
func emptyToDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
