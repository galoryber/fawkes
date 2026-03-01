package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "net-user",
		Description:         "Manage local user accounts and group membership via Win32 API (T1136.001, T1098)",
		HelpString:          "net-user -action <add|delete|info|password|group-add|group-remove> -username <name> [-password <pass>] [-group <group>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1136.001", "T1098"},
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
				Choices:          []string{"add", "delete", "info", "password", "group-add", "group-remove"},
				Description:      "Action to perform",
				DefaultValue:     "info",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "username",
				ModalDisplayName: "Username",
				CLIName:          "username",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target username",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "password",
				ModalDisplayName: "Password",
				CLIName:          "password",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Password (required for add and password actions)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "group",
				ModalDisplayName: "Group",
				CLIName:          "group",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Local group name (required for group-add and group-remove actions)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "comment",
				ModalDisplayName: "Comment",
				CLIName:          "comment",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Account comment/description (optional, for add action)",
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
			action, _ := taskData.Args.GetStringArg("action")
			username, _ := taskData.Args.GetStringArg("username")
			display := fmt.Sprintf("%s user: %s", action, username)
			response.DisplayParams = &display
			switch action {
			case "add":
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:          taskData.Task.ID,
					BaseArtifactType: "API Call",
					ArtifactMessage: fmt.Sprintf("NetUserAdd(%s)", username),
				})
			case "delete":
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:          taskData.Task.ID,
					BaseArtifactType: "API Call",
					ArtifactMessage: fmt.Sprintf("NetUserDel(%s)", username),
				})
			case "password":
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:          taskData.Task.ID,
					BaseArtifactType: "API Call",
					ArtifactMessage: fmt.Sprintf("NetUserSetInfo(%s, level=1003)", username),
				})
			case "group-add":
				group, _ := taskData.Args.GetStringArg("group")
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:          taskData.Task.ID,
					BaseArtifactType: "API Call",
					ArtifactMessage: fmt.Sprintf("NetLocalGroupAddMembers(%s, %s)", group, username),
				})
			case "group-remove":
				group, _ := taskData.Args.GetStringArg("group")
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:          taskData.Task.ID,
					BaseArtifactType: "API Call",
					ArtifactMessage: fmt.Sprintf("NetLocalGroupDelMembers(%s, %s)", group, username),
				})
			}
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
