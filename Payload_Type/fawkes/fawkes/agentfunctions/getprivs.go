package agentfunctions

import (
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "getprivs",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "getprivs_new.js"),
			Author:     "@galoryber",
		},
		Description:         "List, enable, disable, or strip token privileges. Strip disables all non-essential privileges to reduce EDR detection surface.",
		HelpString:          "getprivs\ngetprivs -action list\ngetprivs -action enable -privilege SeDebugPrivilege\ngetprivs -action disable -privilege SeDebugPrivilege\ngetprivs -action strip",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.002"}, // Access Token Manipulation: Create Process with Token
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
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
			if input != "" {
				if input == "" {
				return nil
			}
			return args.LoadArgsFromJSONString(input)
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
		TaskFunctionProcessResponse: nil,
	})
}
