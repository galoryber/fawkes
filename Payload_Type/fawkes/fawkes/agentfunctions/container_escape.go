package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

var containerEscapeVectors = []string{"Docker socket", "cgroup", "nsenter", "mount-host", "privileged", "cap_sys_admin", "host PID"}

func detectEscapeVectors(responseText string) []string {
	var found []string
	lower := strings.ToLower(responseText)
	for _, v := range containerEscapeVectors {
		if strings.Contains(lower, strings.ToLower(v)) {
			found = append(found, v)
		}
	}
	return found
}

// countRBACFindings parses the k8s-rbac action's output and returns the count
// of `[CRIT]`/`[WARN]` finding lines. Used by ProcessResponse to drive event
// logging without re-running the analysis on the Mythic side.
func countRBACFindings(responseText string) (crit int, warn int) {
	for _, line := range strings.Split(responseText, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "[CRIT]"):
			crit++
		case strings.HasPrefix(trimmed, "[WARN]"):
			warn++
		}
	}
	return
}

// countK8sNodes parses the k8s-nodes action's "Nodes: N" header and returns N.
// Falls back to counting "[*] <nodename>" lines if the header isn't present.
func countK8sNodes(responseText string) int {
	for _, line := range strings.Split(responseText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Nodes:") {
			var n int
			fmt.Sscanf(trimmed, "Nodes: %d", &n)
			if n > 0 {
				return n
			}
		}
	}
	n := 0
	for _, line := range strings.Split(responseText, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "[*] ") {
			n++
		}
	}
	return n
}

// countEtcdUnauth parses the k8s-etcd action's per-endpoint status lines
// and returns (unauth, total). The orchestrator emits a "[UNAUTH]
// <url>" line per endpoint that accepted an anonymous read; total comes
// from the "Endpoints to probe: N" header (with a fallback to counting
// "  [" status lines).
func countEtcdUnauth(responseText string) (unauth int, total int) {
	for _, line := range strings.Split(responseText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Endpoints to probe:") {
			fmt.Sscanf(trimmed, "Endpoints to probe: %d", &total)
		}
		if strings.HasPrefix(trimmed, "[UNAUTH]") {
			unauth++
		}
	}
	if total == 0 {
		// Fallback: count "[STATUS]" lines in the probe-results section.
		for _, line := range strings.Split(responseText, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "[") && strings.Contains(t, "] http") {
				total++
			}
		}
	}
	return
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "container-escape",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "containerescape_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Container escape and K8s operations — enumerate breakout vectors, exploit Docker/cgroup/nsenter, and interact with Kubernetes API (RBAC privesc paths, nodes, secrets, etcd unauth probe, pod exec) (T1611, T1610, T1613, T1552.007, T1069.003)",
		HelpString:          "container-escape -action <check|docker-sock|cgroup|nsenter|mount-host|k8s-enum|k8s-secrets|k8s-rbac|k8s-nodes|k8s-etcd|k8s-deploy|k8s-exec> [-command '<cmd>'] [-image alpine] [-path /dev/sda1|<namespace>|*]",
		Version:             4,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1611", "T1610", "T1613", "T1552.007", "T1069.003", "T1087.004"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Linux"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"check", "docker-sock", "cgroup", "nsenter", "mount-host", "k8s-enum", "k8s-secrets", "k8s-rbac", "k8s-nodes", "k8s-etcd", "k8s-deploy", "k8s-exec"},
				Description:      "Escape technique or K8s operation: check (enumerate vectors), docker-sock, cgroup, nsenter, mount-host, k8s-enum (discover pods/services), k8s-secrets (read secrets), k8s-rbac (ClusterRoles/RoleBindings + privesc paths; -path <ns>|*), k8s-nodes (node attack-surface: kubelet/OS/kernel/CIDR/taints), k8s-etcd (discover etcd endpoints + unauthenticated probe; -path <namespace> override), k8s-deploy (create pod), k8s-exec (run in pod)",
				DefaultValue:     "check",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "command",
				ModalDisplayName: "Host Command",
				CLIName:          "command",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Command to execute on host (docker-sock/cgroup/nsenter), secret name (k8s-secrets), command to run (k8s-deploy), or 'podname command' (k8s-exec)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "image",
				ModalDisplayName: "Docker Image",
				CLIName:          "image",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Container image for docker-sock/k8s-deploy/k8s-exec (default: alpine)",
				DefaultValue:     "alpine",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "Device Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Block device path for mount-host; K8s namespace override for k8s-enum/k8s-secrets/k8s-deploy/k8s-exec/k8s-etcd; k8s-rbac accepts <ns>, comma-separated <ns1,ns2>, or '*' for every namespace",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC AUDIT: Container escape check completed. Cgroup, namespace, and capability enumeration generate audit events. Successful escape attempts modify host-level resources visible to host EDR."
			switch action {
			case "k8s-rbac":
				msg = "OPSEC AUDIT: K8s RBAC enumeration completed. /apis/rbac.authorization.k8s.io GETs land in the audit log with the caller's service account; SelfSubjectRulesReview specifically records the calling subject. Findings tagged crit/warn/info indicate privilege escalation paths usable from this callback."
			case "k8s-nodes":
				msg = "OPSEC AUDIT: K8s node enumeration completed. /api/v1/nodes is a common reconnaissance target — cluster admission webhooks (Falco, Gatekeeper) frequently alert on list operations from non-control-plane service accounts."
			case "k8s-etcd":
				msg = "OPSEC AUDIT: K8s etcd probe completed. Two distinct audit trails: (1) kube-system pod listing landed in the apiserver audit log; (2) the direct TCP/HTTP connections to etcd's client port :2379 are visible to host EDR + any NetFlow collector. Falco's default ruleset includes an `Etcd Connection Not From Allowed Source` rule that alerts on this exact traffic."
			}
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			return args.LoadArgsFromJSONString(input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: Container escape attempts to break out of container isolation to the host OS. Highly detectable by container security tools (Falco, Sysdig, Aqua). May trigger alerts for mount namespace manipulation, cgroup abuse, or /proc filesystem access."
			switch action {
			case "k8s-rbac":
				msg = "OPSEC WARNING: K8s RBAC enumeration issues authenticated GETs to /apis/rbac.authorization.k8s.io/v1/{cluster,}rol{es,ebindings} and a SelfSubjectRulesReview. Every request lands in the cluster audit log with the calling service account identity. List operations against cluster-scoped resources are a high-signal recon indicator that Falco/Gatekeeper and managed K8s providers (GKE/EKS/AKS Threat Detection) commonly alert on."
			case "k8s-nodes":
				msg = "OPSEC WARNING: K8s node enumeration calls /api/v1/nodes which is restricted to cluster-admin-equivalent roles in most clusters. A 403 from this endpoint is itself a high-signal alert. Successful enumeration reveals kubelet versions (CVE-hunt), OS images, kernel versions (LPE-hunt), pod CIDRs (network plan), and taints (control-plane vs worker topology) — all suitable for the audit log."
			case "k8s-etcd":
				msg = "OPSEC WARNING: K8s etcd probe runs in two phases. Phase 1 inspects kube-system pod specs to scrape --etcd-servers/--listen-client-urls from control-plane container args (audit log: GET /api/v1/namespaces/kube-system/pods). Phase 2 issues unauthenticated GET /version requests against each discovered endpoint at :2379. Direct connections to etcd's client port are extremely uncommon outside the apiserver process — IDS, NetFlow, and Falco (`Etcd Connection Not From Allowed Source` default rule) all flag this. A successful unauthenticated read against etcd is a full cluster compromise: every secret, token, and config is unencrypted at rest in the keyspace."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "Process Create", "Container escape attempt")
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			if action == "check" {
				for _, v := range detectEscapeVectors(responseText) {
					createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
						fmt.Sprintf("[Container Escape] Vector available: %s", v))
				}
			} else if strings.HasPrefix(action, "k8s-") {
				createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
					fmt.Sprintf("[K8s] %s operation on %s", action, processResponse.TaskData.Callback.Host))
				if action == "k8s-secrets" && strings.Contains(responseText, "secret(s)") {
					logOperationEvent(processResponse.TaskData.Task.ID,
						fmt.Sprintf("[CREDENTIAL ACCESS] K8s secrets enumerated on %s", processResponse.TaskData.Callback.Host), true)
				}
				if action == "k8s-rbac" {
					critCount, warnCount := countRBACFindings(responseText)
					if critCount > 0 {
						logOperationEvent(processResponse.TaskData.Task.ID,
							fmt.Sprintf("[PRIVESC] K8s RBAC: %d CRIT path(s) on %s", critCount, processResponse.TaskData.Callback.Host), true)
					}
					if critCount+warnCount > 0 {
						createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
							fmt.Sprintf("[K8s RBAC] %d crit / %d warn finding(s)", critCount, warnCount))
					}
				}
				if action == "k8s-nodes" {
					if nodeCount := countK8sNodes(responseText); nodeCount > 0 {
						logOperationEvent(processResponse.TaskData.Task.ID,
							fmt.Sprintf("[RECON] K8s nodes enumerated: %d node(s) on %s", nodeCount, processResponse.TaskData.Callback.Host), true)
					}
				}
				if action == "k8s-etcd" {
					unauth, total := countEtcdUnauth(responseText)
					if unauth > 0 {
						logOperationEvent(processResponse.TaskData.Task.ID,
							fmt.Sprintf("[CREDENTIAL ACCESS] K8s etcd: %d unauthenticated endpoint(s) on %s (full cluster compromise)", unauth, processResponse.TaskData.Callback.Host), true)
					}
					if total > 0 {
						createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
							fmt.Sprintf("[K8s etcd] %d unauth / %d probed endpoint(s)", unauth, total))
					}
				}
			} else if strings.Contains(responseText, "Success") || strings.Contains(responseText, "success") {
				createArtifact(processResponse.TaskData.Task.ID, "Process Create",
					fmt.Sprintf("[Container Escape] Successful breakout via %s", action))
			}
			return response
		},
	})
}
