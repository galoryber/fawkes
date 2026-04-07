package agentfunctions

import (
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "compress",
		Description:         "Create, list, extract, or stage encrypted archives. Stage action collects files into AES-256-GCM encrypted archives for exfiltration.",
		HelpString:          "compress -action create|list|extract|stage -path <dir_or_file> [-format zip|tar.gz] [-output path] [-pattern *.txt] [-max_depth 10] [-max_size 104857600]",
		Version:             2,
		MitreAttackMappings: []string{"T1560.001", "T1074.001"}, // Archive via Utility, Local Data Staging
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Action to perform",
				Choices:       []string{"create", "list", "extract", "stage"},
				DefaultValue:  "create",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "path",
				CLIName:       "path",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Source path (file or directory for create, zip file for list/extract)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "output",
				CLIName:       "output",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Output path (zip file for create, directory for extract). Auto-generated if omitted.",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "format",
				CLIName:       "format",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Archive format. Auto-detected from file extension for list/extract.",
				Choices:       []string{"zip", "tar.gz"},
				DefaultValue:  "zip",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "pattern",
				CLIName:       "pattern",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Glob pattern to filter files (e.g. *.txt, *.docx, password*)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "max_depth",
				CLIName:       "max_depth",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Maximum directory recursion depth (default: 10)",
				DefaultValue:  10,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     6,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "max_size",
				CLIName:       "max_size",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Skip files larger than this (bytes, default: 104857600 = 100MB)",
				DefaultValue:  104857600,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     7,
						GroupName:            "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input != "" {
				return args.LoadArgsFromJSONString(input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: Compressing files for staging/exfiltration (T1560.001). Bulk file compression into archives is a data staging indicator."
			if action == "stage" {
				msg = "OPSEC WARNING: Data staging with AES-256-GCM encryption (T1074.001 + T1560.001). Creates encrypted archive in temp directory. Disk write of encrypted archive may trigger DLP or endpoint monitoring. The encryption key is returned in task output — protect it."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			// Detect stage action output (JSON with encryption_key field)
			var stageResult struct {
				ArchivePath string `json:"archive_path"`
				FileCount   int    `json:"file_count"`
				ArchiveSize int64  `json:"archive_size"`
				SourcePath  string `json:"source_path"`
			}
			if err := json.Unmarshal([]byte(responseText), &stageResult); err == nil && stageResult.ArchivePath != "" {
				createArtifact(processResponse.TaskData.Task.ID, "File Write",
					fmt.Sprintf("Encrypted staging archive: %s (%d files, %d bytes) from %s",
						stageResult.ArchivePath, stageResult.FileCount, stageResult.ArchiveSize, stageResult.SourcePath))
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[DATA STAGING] compress stage: %d files (%d bytes) staged to %s from %s",
						stageResult.FileCount, stageResult.ArchiveSize, stageResult.ArchivePath, stageResult.SourcePath), true)
				tagTask(processResponse.TaskData.Task.ID, "DATA_STAGED",
					fmt.Sprintf("Encrypted staging: %d files (%d bytes) at %s",
						stageResult.FileCount, stageResult.ArchiveSize, stageResult.ArchivePath))
			}
			return response
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			if displayParams, err := task.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			path, _ := task.Args.GetStringArg("path")
			createArtifact(task.Task.ID, "File Write", fmt.Sprintf("File compression of %s", path))
			return response
		},
	})
}
