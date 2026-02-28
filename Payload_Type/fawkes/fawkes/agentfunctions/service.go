package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "service",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "service_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Manage Windows services via SCM API — query, start, stop, create, delete, list (T1543.003)",
		HelpString:          "service -action <query|start|stop|create|delete|list> -name <service_name> [-binpath <path>] [-display <name>] [-start <auto|demand|disabled>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1543.003"},
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
				Choices:          []string{"query", "start", "stop", "create", "delete", "list"},
				Description:      "Action to perform on the service",
				DefaultValue:     "query",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "name",
				ModalDisplayName: "Service Name",
				CLIName:          "name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Name of the Windows service (e.g., Spooler, wuauserv)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "binpath",
				ModalDisplayName: "Binary Path",
				CLIName:          "binpath",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to the service binary (required for create)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "display",
				ModalDisplayName: "Display Name",
				CLIName:          "display",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Display name for the service (optional, for create)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "start",
				ModalDisplayName: "Start Type",
				CLIName:          "start",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"demand", "auto", "disabled"},
				Description:      "Service start type: demand (manual), auto (automatic), disabled",
				DefaultValue:     "demand",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionOPSECPre: nil,
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
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
			name, _ := taskData.Args.GetStringArg("name")
			switch action {
			case "create":
				binpath, _ := taskData.Args.GetStringArg("binpath")
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM CreateService %s binpath=%q", name, binpath))
			case "start":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM StartService %s", name))
			case "stop":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM ControlService(Stop) %s", name))
			case "delete":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM DeleteService %s", name))
			}
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
