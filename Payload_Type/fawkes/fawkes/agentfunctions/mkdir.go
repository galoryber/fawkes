package agentfunctions

import (
	"encoding/json"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/mitchellh/mapstructure"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "mkdir",
		Description:         "Create a new directory (creates parent directories if needed)",
		HelpString:          "mkdir <directory>",
		Version:             2,
		MitreAttackMappings: []string{"T1106"}, // Native API
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "mkdir_new.js"), Author: "@galoryber"},
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
				OpsecPreMessage:    "OPSEC WARNING: Directory creation (T1106). Creating directories leaves MFT entries and USN journal records. Directories in temp, startup, or system paths may trigger EDR behavioral detection.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Directory created. New directory entry in filesystem with current timestamps — visible in USN journal, $MFT, and EDR file monitoring. Consider using existing directories or timestomping to blend in.",
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
				createArtifact(task.Task.ID, "File Create", "mkdir "+displayParams)
			}
			return response
		},
	})
}
