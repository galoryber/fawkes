package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "vss",
		Description:         "Manage Volume Shadow Copies — list, create, delete, and extract files from shadow copies. Useful for extracting locked files like NTDS.dit or SAM.",
		HelpString:          "vss -action <list|create|delete|extract> [-volume C:\\] [-id <shadow_id_or_device_path>] [-source <path>] [-dest <path>]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.003"}, // OS Credential Dumping: NTDS
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"list", "create", "delete", "extract"},
				DefaultValue:  "list",
				Description:   "Action: list shadow copies, create new, delete existing, or extract a file",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "volume",
				CLIName:       "volume",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "C:\\",
				Description:   "Volume to create shadow copy of (for create action, default: C:\\)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "id",
				CLIName:       "id",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Shadow copy ID (for delete) or device path (for extract, e.g., \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "source",
				CLIName:       "source",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Path within shadow copy to extract (e.g., \\Windows\\NTDS\\ntds.dit)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "dest",
				CLIName:       "dest",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Local destination path to save extracted file",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
						GroupName:           "Default",
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: Volume Shadow Copy operations. "
			switch action {
			case "create":
				msg += "Creating a shadow copy generates Event ID 8224 (VSS) and may trigger alerts for credential access preparation (SAM/NTDS.dit extraction)."
			case "delete":
				msg += "Deleting shadow copies is a well-known ransomware indicator (Event ID 524). High-fidelity detection rule in most SIEM/EDR."
			case "extract":
				msg += "Extracting files from shadow copies bypasses file locks — commonly used for SAM/SYSTEM/NTDS.dit extraction."
			default:
				msg += "Listing shadow copies is low risk but may indicate pre-attack reconnaissance."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := fmt.Sprintf("action: %s", action)
			switch action {
			case "create":
				vol, _ := taskData.Args.GetStringArg("volume")
				display += fmt.Sprintf(", volume: %s", vol)
			case "delete":
				delID, _ := taskData.Args.GetStringArg("id")
				display += fmt.Sprintf(", id: %s", delID)
			case "extract":
				src, _ := taskData.Args.GetStringArg("source")
				display += fmt.Sprintf(", source: %s", src)
			}
			response.DisplayParams = &display
			switch action {
			case "create":
				volume, _ := taskData.Args.GetStringArg("volume")
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("Win32_ShadowCopy.Create volume=%s", volume))
			case "delete":
				id, _ := taskData.Args.GetStringArg("id")
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("Win32_ShadowCopy.Delete_ id=%s", id))
			case "extract":
				source, _ := taskData.Args.GetStringArg("source")
				dest, _ := taskData.Args.GetStringArg("dest")
				createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("VSS extract %s to %s", source, dest))
			}
			return response
		},
	})
}
