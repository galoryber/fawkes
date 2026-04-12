package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "hash",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "hash_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Compute file hashes (MD5, SHA-1, SHA-256, SHA-512). Single files or directories with pattern filtering.",
		HelpString:          "hash -path /etc/passwd\nhash -path C:\\Windows\\System32 -algorithm md5 -pattern *.dll -recursive true\nhash -path /tmp -algorithm sha512 -max_files 100",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1083"},
		SupportedUIFeatures: []string{"file_browser:download"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "File or Directory Path",
				Description:      "Path to file or directory to hash",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "algorithm",
				CLIName:          "algorithm",
				ModalDisplayName: "Hash Algorithm",
				Description:      "Hash algorithm to use",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				DefaultValue:     "sha256",
				Choices:          []string{"md5", "sha1", "sha256", "sha512"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "recursive",
				CLIName:          "recursive",
				ModalDisplayName: "Recursive",
				Description:      "Recurse into subdirectories (for directory paths)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "pattern",
				CLIName:          "pattern",
				ModalDisplayName: "File Pattern",
				Description:      "Glob pattern to filter files (e.g., *.exe, *.dll)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "max_files",
				CLIName:          "max_files",
				ModalDisplayName: "Max Files",
				Description:      "Maximum number of files to hash (default: 500)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     500,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
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
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			path, _ := processResponse.TaskData.Args.GetStringArg("path")
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" || path == "" {
				return response
			}
			algorithm, _ := processResponse.TaskData.Args.GetStringArg("algorithm")
			// Count hashed files from summary line
			var fileCount int
			for _, line := range strings.Split(responseText, "\n") {
				if strings.HasPrefix(line, "[*]") && strings.Contains(line, "files hashed") {
					fmt.Sscanf(line, "[*] %d files hashed", &fileCount)
					break
				}
			}
			if fileCount > 0 {
				createArtifact(processResponse.TaskData.Task.ID, "File Discovery",
					fmt.Sprintf("hash %s: %d files hashed (%s)", path, fileCount, algorithm))
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: File hashing completed. File read operations update access timestamps. Hash values can be cross-referenced with threat intel feeds. No persistent artifacts created.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			path, _ := taskData.Args.GetStringArg("path")
			algorithm, _ := taskData.Args.GetStringArg("algorithm")
			display := fmt.Sprintf("%s %s", path, algorithm)
			response.DisplayParams = &display
			return response
		},
	})
}
