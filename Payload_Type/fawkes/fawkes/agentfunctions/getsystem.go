package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "getsystem",
		Description:         "Privilege escalation. Windows: SYSTEM via token steal or DCOM potato. Linux: root via sudo, SUID, capabilities check. macOS: root via sudo or osascript elevation prompt.",
		HelpString:          "# Windows\ngetsystem -technique steal\ngetsystem -technique potato\n# Linux\ngetsystem -technique check\ngetsystem -technique sudo\n# macOS\ngetsystem -technique check\ngetsystem -technique sudo\ngetsystem -technique osascript",
		Version:             4,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001", "T1548.001", "T1548.003", "T1059.002"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "technique",
				ModalDisplayName: "Technique",
				CLIName:          "technique",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"steal", "potato", "check", "sudo", "osascript"},
				Description:      "Windows: steal (token theft, needs admin) or potato (DCOM OXID, needs service). Linux: check (enumerate vectors) or sudo (attempt elevation). macOS: check, sudo, or osascript (admin prompt).",
				DefaultValue:     "check",
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
			technique, _ := taskData.Args.GetStringArg("technique")
			var msg string
			switch technique {
			case "steal":
				msg = "OPSEC WARNING: Token theft from SYSTEM process via OpenProcessToken + DuplicateTokenEx. Requires SeDebugPrivilege. Token manipulation is a high-fidelity EDR detection."
			case "potato":
				msg = "OPSEC WARNING: DCOM potato privilege escalation via OXID resolution hook + named pipe impersonation. Creates artifacts in RPC dispatch table."
			case "sudo":
				msg = "OPSEC WARNING: Privilege escalation via sudo. Command execution visible in process tree and auth.log/secure. Failed attempts logged."
			case "osascript":
				msg = "OPSEC WARNING: Privilege escalation via AppleScript admin prompt. Triggers a visible UI dialog. User may deny or report. Auth attempt logged in unified logging."
			case "check":
				msg = "OPSEC NOTE: Enumerating privilege escalation vectors. Low risk — reads filesystem and checks permissions. sudo -l may generate an auth log entry."
			default:
				msg = "OPSEC WARNING: Privilege escalation attempt. May trigger alerts."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			// On successful SYSTEM escalation, update callback IntegrityLevel
			if !strings.Contains(responseText, "Successfully elevated to SYSTEM") {
				return response
			}
			systemLevel := 4 // SYSTEM integrity
			update := mythicrpc.MythicRPCCallbackUpdateMessage{
				AgentCallbackID: &processResponse.TaskData.Callback.AgentCallbackID,
				IntegrityLevel:    &systemLevel,
			}
			// Parse user from "New:" line
			user := ""
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if val := extractField(trimmed, "New:"); val != "" {
					user = val
					update.User = &val
					break
				}
			}
			if _, err := mythicrpc.SendMythicRPCCallbackUpdate(update); err != nil {
				logging.LogError(err, "Failed to update callback metadata after getsystem")
			}
			tagTask(processResponse.TaskData.Task.ID, "SYSTEM",
				fmt.Sprintf("SYSTEM-level access obtained on %s", processResponse.TaskData.Callback.Host))
			// Register SYSTEM token with Mythic's token tracker
			if user == "" {
				user = "NT AUTHORITY\\SYSTEM"
			}
			host := processResponse.TaskData.Callback.Host
			if _, err := mythicrpc.SendMythicRPCCallbackTokenCreate(mythicrpc.MythicRPCCallbackTokenCreateMessage{
				TaskID: processResponse.TaskData.Task.ID,
				CallbackTokens: []mythicrpc.MythicRPCCallbackTokenData{
					{
						Action:  "add",
						Host:    &host,
						TokenID: uint64(processResponse.TaskData.Task.ID),
						TokenInfo: &mythicrpc.MythicRPCTokenCreateTokenData{
							User: user,
						},
					},
				},
			}); err != nil {
				logging.LogError(err, "Failed to register SYSTEM token with Mythic")
			}
			return response
		},
	})
}
