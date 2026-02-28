package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "screenshot",
		Description:         "Capture a screenshot of the current desktop session. Captures all monitors.",
		HelpString:          "screenshot",
		Version:             1,
		MitreAttackMappings: []string{"T1113"}, // Screen Capture
		SupportedUIFeatures: []string{"screenshot:show"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return nil
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			display := fmt.Sprintf("Screen capture")
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", "Screen capture (platform-specific: GDI BitBlt on Windows, Xlib on Linux, CGDisplayCreateImage on macOS)")
			return response
		},
	})
}
