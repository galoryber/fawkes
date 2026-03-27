package agentfunctions

import (
	"encoding/json"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "getprivs",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "getprivs_new.js"),
			Author:     "@galoryber",
		},
		Description:         "List, enable, disable, or strip token privileges. On Windows, shows token privileges with enable/disable/strip support. On Linux, shows process capabilities (CapEff/CapPrm) and security context (SELinux/AppArmor). On macOS, shows entitlements, sandbox status, and group memberships.",
		HelpString:          "getprivs\ngetprivs -action list\ngetprivs -action enable -privilege SeDebugPrivilege (Windows only)\ngetprivs -action disable -privilege SeDebugPrivilege (Windows only)\ngetprivs -action strip (Windows only)",
		Version:             3,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.002"}, // Access Token Manipulation: Create Process with Token
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Action: list (show all privs), enable/disable (toggle specific privilege), strip (disable all non-essential)",
				DefaultValue:     "list",
				Choices:          []string{"list", "enable", "disable", "strip"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "privilege",
				ModalDisplayName: "Privilege Name",
				CLIName:          "privilege",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Privilege name (e.g., SeDebugPrivilege). Required for enable/disable actions.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			if action == "" {
				action = "list"
			}
			switch action {
			case "enable", "disable":
				priv, _ := taskData.Args.GetStringArg("privilege")
				createArtifact(taskData.Task.ID, "API Call",
					"AdjustTokenPrivileges("+priv+")")
			case "strip":
				createArtifact(taskData.Task.ID, "API Call",
					"AdjustTokenPrivileges(strip all non-essential)")
			default:
				createArtifact(taskData.Task.ID, "API Call",
					"GetTokenInformation(TokenPrivileges)")
			}
			if displayParams, err := taskData.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
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
			var output struct {
				Identity  string `json:"identity"`
				Integrity string `json:"integrity"`
			}
			if err := json.Unmarshal([]byte(responseText), &output); err != nil {
				return response
			}
			update := mythicrpc.MythicRPCCallbackUpdateMessage{
				AgentCallbackUUID: &processResponse.TaskData.Callback.AgentCallbackID,
			}
			hasUpdate := false
			if output.Integrity != "" {
				level := parseIntegrityLevel(output.Integrity)
				if level >= 0 {
					update.IntegrityLevel = &level
					hasUpdate = true
				}
			}
			if output.Identity != "" {
				update.User = &output.Identity
				hasUpdate = true
			}
			if hasUpdate {
				if _, err := mythicrpc.SendMythicRPCCallbackUpdate(update); err != nil {
					logging.LogError(err, "Failed to update callback metadata from getprivs")
				}
			}
			return response
		},
	})
}
