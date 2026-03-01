package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "persist",
		Description:         "Install or remove persistence mechanisms (registry run key, startup folder, COM hijacking, screensaver hijacking, IFEO debugger)",
		HelpString:          "persist -method <registry|startup-folder|com-hijack|screensaver|ifeo|list> -action <install|remove> [-name <name>] [-path <exe_path>] [-hive <HKCU|HKLM>] [-clsid <CLSID>] [-timeout <seconds>]",
		Version:             3,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1547.001", "T1547.009", "T1546.015", "T1546.002", "T1546.012"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "method",
				ModalDisplayName: "Persistence Method",
				CLIName:          "method",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"registry", "startup-folder", "com-hijack", "screensaver", "ifeo", "list"},
				Description:      "Persistence method: registry (Run key), startup-folder (copy to Startup), com-hijack (CLSID override), screensaver (idle trigger), ifeo (debugger hijack), or list (enumerate all)",
				DefaultValue:     "registry",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"install", "remove"},
				Description:      "Install or remove the persistence entry",
				DefaultValue:     "install",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "name",
				ModalDisplayName: "Entry Name",
				CLIName:          "name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Name for the persistence entry (registry value name or startup folder filename)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "Executable Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to the executable to persist. Defaults to the current agent binary.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "hive",
				ModalDisplayName: "Registry Hive",
				CLIName:          "hive",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"HKCU", "HKLM"},
				Description:      "Registry hive for Run key persistence (HKCU = current user, HKLM = all users, requires admin)",
				DefaultValue:     "HKCU",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "clsid",
				ModalDisplayName: "CLSID",
				CLIName:          "clsid",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "COM object CLSID to hijack (for com-hijack method). Default: {42aedc87-2188-41fd-b9a3-0c966feabec1} (MruPidlList, loaded by explorer.exe)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "timeout",
				ModalDisplayName: "Timeout (seconds)",
				CLIName:          "timeout",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Idle timeout in seconds before screensaver triggers (for screensaver method). Default: 60",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre:    nil,
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
			method, _ := taskData.Args.GetStringArg("method")
			action, _ := taskData.Args.GetStringArg("action")
			name, _ := taskData.Args.GetStringArg("name")
			display := fmt.Sprintf("%s %s", action, method)
			response.DisplayParams = &display
			if action == "install" {
				switch method {
				case "registry":
					hive, _ := taskData.Args.GetStringArg("hive")
					createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\%s", hive, name))
				case "startup-folder":
					createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("Startup folder: %s", name))
				case "com-hijack":
					clsid, _ := taskData.Args.GetStringArg("clsid")
					if clsid == "" {
						clsid = "{42aedc87-2188-41fd-b9a3-0c966feabec1}"
					}
					path, _ := taskData.Args.GetStringArg("path")
					createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("HKCU\\Software\\Classes\\CLSID\\%s\\InprocServer32 = %s", clsid, path))
				case "screensaver":
					path, _ := taskData.Args.GetStringArg("path")
					createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE = %s", path))
				case "ifeo":
					path, _ := taskData.Args.GetStringArg("path")
					createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s\\Debugger = %s", name, path))
				}
			}
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
