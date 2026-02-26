package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "reg-save",
		Description:         "Export registry hives to files for offline credential extraction. Use 'creds' action to export SAM+SECURITY+SYSTEM in one step. Requires SYSTEM privileges.",
		HelpString:          "reg-save -action <save|creds> [-hive HKLM] [-path SAM] [-output C:\\Temp\\sam.hiv]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.002", "T1003.004"}, // SAM + LSA Secrets
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"save", "creds"},
				DefaultValue:  "save",
				Description:   "Action: save (export specific hive/key) or creds (export SAM+SECURITY+SYSTEM for offline extraction)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "hive",
				CLIName:       "hive",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "HKLM",
				Description:   "Registry hive root (HKLM, HKCU, HKCR, HKU). For save action only.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "path",
				CLIName:       "path",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Registry path to export (e.g., SAM, SECURITY, SYSTEM, SOFTWARE). For save action only.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "output",
				CLIName:       "output",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Output file path. For save: required. For creds: directory (default: C:\\Windows\\Temp).",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "Default",
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
			if action == "creds" {
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "File Create",
					ArtifactMessage:  "RegSaveKeyEx — SAM+SECURITY+SYSTEM hive export",
				})
			} else {
				path, _ := taskData.Args.GetStringArg("path")
				output, _ := taskData.Args.GetStringArg("output")
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "File Create",
					ArtifactMessage:  fmt.Sprintf("RegSaveKeyEx — %s → %s", path, output),
				})
			}
			return response
		},
	})
}
