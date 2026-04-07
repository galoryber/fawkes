package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "vss",
		Description:         "Manage Volume Shadow Copies and system recovery. List, create, delete, extract files. delete-all and inhibit-recovery for ransomware emulation (T1490).",
		HelpString:          "vss -action <list|create|delete|delete-all|extract|inhibit-recovery> [-volume C:\\] [-id <id>] [-source <path>] [-dest <path>] [-confirm true]",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.003", "T1490"}, // OS Credential Dumping + Inhibit System Recovery
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"list", "create", "delete", "delete-all", "extract", "inhibit-recovery"},
				DefaultValue:  "list",
				Description:   "Action: list, create, delete (by ID), delete-all (all copies), extract (file from copy), inhibit-recovery (comprehensive T1490)",
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
			{
				Name:          "confirm",
				CLIName:       "confirm",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:  false,
				Description:   "Required for destructive actions (delete-all, inhibit-recovery). Safety check to prevent accidental execution.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     6,
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
			case "delete-all":
				msg += "CRITICAL: Deleting ALL shadow copies is the #1 ransomware indicator (T1490). Triggers Event ID 524, Defender, CrowdStrike, SentinelOne, and every SIEM. Use only in authorized ransomware emulation."
			case "inhibit-recovery":
				msg += "CRITICAL: Comprehensive recovery inhibition (T1490). Deletes all shadow copies, disables Windows Recovery, deletes backup catalog. Multiple high-fidelity indicators. Spawns bcdedit.exe and wbadmin.exe. Use only in authorized ransomware emulation."
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
			case "delete-all":
				display += " (ALL shadow copies)"
			case "inhibit-recovery":
				display += " (shadows + recovery + backups)"
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
			case "delete-all":
				createArtifact(taskData.Task.ID, "API Call", "Win32_ShadowCopy.Delete_ (ALL shadow copies)")
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[IMPACT] vss delete-all: deleting ALL shadow copies on %s (T1490)", taskData.Callback.Host), true)
			case "inhibit-recovery":
				createArtifact(taskData.Task.ID, "API Call", "T1490: Delete shadows + bcdedit + wbadmin (recovery inhibition)")
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[IMPACT] vss inhibit-recovery: comprehensive recovery inhibition on %s (T1490)", taskData.Callback.Host), true)
			case "extract":
				source, _ := taskData.Args.GetStringArg("source")
				dest, _ := taskData.Args.GetStringArg("dest")
				createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("VSS extract %s to %s", source, dest))
			}
			return response
		},
	})
}
