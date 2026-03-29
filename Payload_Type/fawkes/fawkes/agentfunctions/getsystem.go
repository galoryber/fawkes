package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "getsystem",
		Description:         "Elevate to SYSTEM via token steal (SeDebugPrivilege) or DCOM potato (SeImpersonatePrivilege)",
		HelpString:          "getsystem [-technique steal|potato]",
		Version:             3,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "technique",
				ModalDisplayName: "Technique",
				CLIName:          "technique",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"steal", "potato"},
				Description:      "steal = token theft from SYSTEM process (needs SeDebugPrivilege/admin). potato = DCOM OXID resolution hook (needs SeImpersonatePrivilege/service account).",
				DefaultValue:     "steal",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:  taskData.Task.ID,
				Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage: "OPSEC WARNING: Attempting SYSTEM privilege escalation via named pipe impersonation. " +
					"Creates a named pipe and waits for a privileged connection. " +
					"May trigger alerts for token manipulation or privilege escalation.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: SYSTEM privilege escalation configured. Named pipe impersonation artifacts will be created.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			if err := args.LoadArgsFromJSONString(input); err != nil {
				// Plain text fallback: treat input as technique name
				input = strings.TrimSpace(input)
				return args.SetArgValue("technique", input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			technique, _ := taskData.Args.GetStringArg("technique")
			if technique == "" {
				technique = "steal"
			}
			display := fmt.Sprintf("technique: %s", technique)
			response.DisplayParams = &display
			switch technique {
			case "potato":
				createArtifact(taskData.Task.ID, "DCOM OXID Hook", "combase.dll RPC dispatch table hook + named pipe impersonation")
			default:
				createArtifact(taskData.Task.ID, "Token Steal", "OpenProcess + OpenProcessToken + DuplicateTokenEx on SYSTEM process")
			}
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
