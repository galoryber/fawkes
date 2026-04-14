package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ads",
		Description:         "Manage NTFS Alternate Data Streams — write, read, list, or delete hidden streams (T1564.004)",
		HelpString:          "ads -action <write|read|list|delete> -file <path> [-stream <name>] [-data <content>] [-hex true]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1564.004"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"write", "read", "list", "delete"},
				Description:      "Action to perform: write, read, list, or delete ADS",
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "file",
				ModalDisplayName: "File Path",
				CLIName:          "file",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target file or directory path",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "stream",
				ModalDisplayName: "Stream Name",
				CLIName:          "stream",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Name of the alternate data stream (without colon prefix)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "data",
				ModalDisplayName: "Data",
				CLIName:          "data",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Data to write to the stream (text or hex-encoded binary)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "hex",
				ModalDisplayName: "Hex Mode",
				CLIName:          "hex",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "If true, data is treated as hex-encoded bytes (write) or output as hex dump (read)",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ads_new.js"), Author: "@galoryber"},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			switch action {
			case "write":
				msg = "OPSEC WARNING: Writing NTFS Alternate Data Stream (T1564.004). ADS writes are logged by Sysmon Event ID 15 (FileCreateStreamHash) and EDR file-write telemetry. Hidden data in ADS is discoverable by forensic tools."
			case "delete":
				msg = "OPSEC WARNING: Deleting NTFS Alternate Data Stream (T1564.004). ADS deletion may trigger Sysmon Event ID 23 (FileDelete) and indicate artifact cleanup."
			default:
				msg = "OPSEC WARNING: NTFS Alternate Data Stream enumeration (T1564.004). ADS listing/reading is low-risk but may be correlated with other suspicious file operations."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Alternate Data Stream operation completed. ADS manipulation modifies NTFS metadata visible in MFT entries and EDR file monitoring. Hidden ADS content is a known persistence technique. Sysmon Event ID 15 tracks ADS creation.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			file, _ := taskData.Args.GetStringArg("file")
			stream, _ := taskData.Args.GetStringArg("stream")
			var display string
			if stream != "" {
				display = fmt.Sprintf("%s %s:%s", action, file, stream)
			} else {
				display = fmt.Sprintf("%s %s", action, file)
			}
			response.DisplayParams = &display

			artifactMsg := fmt.Sprintf("NTFS ADS %s: %s", action, file)
			if stream != "" {
				artifactMsg += ":" + stream
			}
			artifactType := "API Call"
			if action == "write" {
				artifactType = "File Write"
			} else if action == "delete" {
				artifactType = "File Delete"
			}
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: artifactType,
				ArtifactMessage:  artifactMsg,
			})
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			if action == "list" && strings.Contains(responseText, ":") {
				// Track discovered ADS entries
				for _, line := range strings.Split(responseText, "\n") {
					trimmed := strings.TrimSpace(line)
					if trimmed != "" && strings.Contains(trimmed, ":") {
						createArtifact(processResponse.TaskData.Task.ID, "File Discovery",
							fmt.Sprintf("[ADS] %s", trimmed))
					}
				}
			}
			return response
		},
	})
}
