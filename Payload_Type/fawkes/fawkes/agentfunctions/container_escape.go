package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "container-escape",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "containerescape_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Container escape and K8s operations — enumerate breakout vectors, exploit Docker/cgroup/nsenter, and interact with Kubernetes API (T1611, T1610, T1613, T1552.007)",
		HelpString:          "container-escape -action <check|docker-sock|cgroup|nsenter|mount-host|k8s-enum|k8s-secrets|k8s-deploy|k8s-exec> [-command '<cmd>'] [-image alpine] [-path /dev/sda1]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1611", "T1610", "T1613", "T1552.007"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"check", "docker-sock", "cgroup", "nsenter", "mount-host", "k8s-enum", "k8s-secrets", "k8s-deploy", "k8s-exec"},
				Description:      "Escape technique or K8s operation: check (enumerate vectors), docker-sock, cgroup, nsenter, mount-host, k8s-enum (discover pods/services), k8s-secrets (read secrets), k8s-deploy (create pod), k8s-exec (run in pod)",
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
				Description:      "Block device path for mount-host, or K8s namespace override for k8s-* actions",
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
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Container escape check completed. Cgroup, namespace, and capability enumeration generate audit events. Successful escape attempts modify host-level resources visible to host EDR.",
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Container escape attempts to break out of container isolation to the host OS. Highly detectable by container security tools (Falco, Sysdig, Aqua). May trigger alerts for mount namespace manipulation, cgroup abuse, or /proc filesystem access.",
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
				// Track discovered escape vectors
				vectors := []string{"Docker socket", "cgroup", "nsenter", "mount-host", "privileged", "cap_sys_admin", "host PID"}
				for _, v := range vectors {
					if strings.Contains(strings.ToLower(responseText), strings.ToLower(v)) {
						createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
							fmt.Sprintf("[Container Escape] Vector available: %s", v))
					}
				}
			} else if strings.HasPrefix(action, "k8s-") {
				createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
					fmt.Sprintf("[K8s] %s operation on %s", action, processResponse.TaskData.Callback.Host))
				if action == "k8s-secrets" && strings.Contains(responseText, "secret(s)") {
					logOperationEvent(processResponse.TaskData.Task.ID,
						fmt.Sprintf("[CREDENTIAL ACCESS] K8s secrets enumerated on %s", processResponse.TaskData.Callback.Host), true)
				}
			} else if strings.Contains(responseText, "Success") || strings.Contains(responseText, "success") {
				createArtifact(processResponse.TaskData.Task.ID, "Process Create",
					fmt.Sprintf("[Container Escape] Successful breakout via %s", action))
			}
			return response
		},
	})
}
