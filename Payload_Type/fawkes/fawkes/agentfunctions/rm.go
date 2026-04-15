package agentfunctions

import (
	"encoding/json"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/mitchellh/mapstructure"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "rm",
		Description:         "Remove a file or directory (recursively removes directories)",
		HelpString:          "rm <path>",
		Version:             2,
		MitreAttackMappings: []string{"T1070.004"}, // Indicator Removal on Host: File Deletion
		SupportedUIFeatures: []string{"file_browser:remove"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			input = strings.TrimSpace(input)
			// Try JSON first (e.g., {"path": "/tmp/test"} or {"full_path": "..."} from file browser)
			var jsonArgs map[string]interface{}
			if err := json.Unmarshal([]byte(input), &jsonArgs); err == nil {
				if fullPath, ok := jsonArgs["full_path"].(string); ok && fullPath != "" {
					args.SetManualArgs(fullPath)
					return nil
				}
				if path, ok := jsonArgs["path"].(string); ok {
					args.SetManualArgs(path)
					return nil
				}
			}
			// Strip surrounding quotes so paths like
			// "C:\Program Data" resolve to C:\Program Data
			if len(input) >= 2 {
				if (input[0] == '"' && input[len(input)-1] == '"') ||
					(input[0] == '\'' && input[len(input)-1] == '\'') {
					input = input[1 : len(input)-1]
				}
			}
			args.SetManualArgs(input)
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			// Check if this is from the file browser (has full_path field)
			fileBrowserData := agentstructs.FileBrowserTask{}
			if err := mapstructure.Decode(input, &fileBrowserData); err == nil && fileBrowserData.FullPath != "" {
				args.SetManualArgs(fileBrowserData.FullPath)
				return nil
			}
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: File deletion (T1070.004). Deleting files leaves MFT entries, USN journal records, and may trigger EDR file-deletion telemetry. Consider secure-delete for anti-forensics or timestomp before removal.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: File deletion completed. Deleted files remain recoverable from USN journal, $MFT residual entries, and volume shadow copies until overwritten. Standard deletion does NOT securely erase data — use securedelete for sensitive artifacts. Recycle Bin bypass (direct delete) is itself a forensic indicator.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			if displayParams, err := task.Args.GetFinalArgs(); err == nil {
				response.DisplayParams = &displayParams
				createArtifact(task.Task.ID, "File Delete", displayParams)
			}
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
			// Update Mythic's file browser tree to reflect the deletion
			if strings.Contains(responseText, "Successfully removed") {
				path := strings.TrimSpace(processResponse.TaskData.Task.Params)
				if path == "" {
					return response
				}
				// Strip JSON wrapper if params came as JSON
				var jsonParams map[string]interface{}
				if err := json.Unmarshal([]byte(path), &jsonParams); err == nil {
					if fp, ok := jsonParams["full_path"].(string); ok && fp != "" {
						path = fp
					} else if p, ok := jsonParams["path"].(string); ok && p != "" {
						path = p
					}
				}
				host := processResponse.TaskData.Callback.Host
				if _, err := mythicrpc.SendMythicRPCFileBrowserRemove(mythicrpc.MythicRPCFileBrowserRemoveMessage{
					TaskID: processResponse.TaskData.Task.ID,
					RemovedFiles: []mythicrpc.MythicRPCFileBrowserRemoveFileBrowserData{
						{
							Host: &host,
							Path: path,
						},
					},
				}); err != nil {
					logging.LogError(err, "Failed to update file browser after rm")
				}
			}
			return response
		},
	})
}
