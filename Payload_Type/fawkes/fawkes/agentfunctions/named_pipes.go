package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "named-pipes",
		Description:         "List named pipes (Windows), Unix domain sockets, and FIFOs (Linux/macOS) for IPC discovery",
		HelpString:          "named-pipes [-filter <pattern>]\nWindows: Enumerates \\\\.\\.\\pipe\\* via FindFirstFile/FindNextFile\nLinux: Reads /proc/net/unix for sockets + scans /tmp,/var/run for FIFOs\nmacOS: Scans /var/run,/tmp,/private/* for sockets and FIFOs",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1083"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "filter",
				ModalDisplayName: "Filter",
				CLIName:          "filter",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Case-insensitive substring filter for pipe names",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "named_pipes_new.js"),
			Author:     "@galoryber",
		},
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
			display := "list"
			filter, _ := taskData.Args.GetStringArg("filter")
			if filter != "" {
				display += fmt.Sprintf(" (filter: %s)", filter)
			}
			response.DisplayParams = &display
			os := taskData.Payload.OS
			if os == "Windows" {
				createArtifact(taskData.Task.ID, "API Call", "FindFirstFile/FindNextFile on \\\\.\\pipe\\*")
			} else {
				createArtifact(taskData.Task.ID, "FileOpen", "/proc/net/unix, /var/run, /tmp")
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
			// Parse named pipe names from output (lines starting with \\.\pipe\ or just pipe names)
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "Named Pipes") || strings.HasPrefix(trimmed, "Filter:") || strings.HasPrefix(trimmed, "---") {
					continue
				}
				if strings.HasPrefix(trimmed, "\\\\.\\pipe\\") || strings.HasPrefix(trimmed, "\\\\") || !strings.ContainsAny(trimmed, " :=") {
					createArtifact(processResponse.TaskData.Task.ID, "File Discovery",
						fmt.Sprintf("[Named Pipe] %s", trimmed))
				}
			}
			return response
		},
	})
}
