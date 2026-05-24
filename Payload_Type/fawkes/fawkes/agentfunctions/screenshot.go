package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func screenshotOPSECMessage(action string, interval, duration int) string {
	if action == "record" {
		return fmt.Sprintf("OPSEC WARNING: Continuous screen recording for %ds at %ds intervals (T1113). "+
			"Sustained screen capture API calls significantly increase detection risk. "+
			"EDR may detect repeated GDI/screencapture invocations. "+
			"Each frame is uploaded to Mythic — sustained C2 traffic is a network indicator. "+
			"Stop with jobkill.", duration, interval)
	}
	return "OPSEC WARNING: Capturing screen contents (T1113). Screen capture API calls may be monitored by EDR. Generates an image artifact in agent memory for exfiltration."
}

type screenshotRecordResult struct {
	Action    string `json:"action"`
	Frames    int    `json:"frames_captured"`
	Duration  string `json:"actual_duration"`
	StoppedBy string `json:"stopped_by"`
}

func parseScreenshotRecordResult(responseText string) (screenshotRecordResult, bool) {
	var result screenshotRecordResult
	if err := json.Unmarshal([]byte(responseText), &result); err != nil || result.Action != "record" {
		return result, false
	}
	return result, true
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "screenshot",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "screenshot_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Capture a screenshot of the current desktop session, or record continuous screenshots at intervals. Captures all monitors.",
		HelpString:          "screenshot\nscreenshot -action record -interval 5 -duration 60 -max_frames 50",
		Version:             2,
		MitreAttackMappings: []string{"T1113"}, // Screen Capture
		SupportedUIFeatures: []string{"screenshot:show"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "single (default) = one screenshot, record = continuous capture at intervals",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"single", "record"},
				DefaultValue:     "single",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "interval",
				CLIName:          "interval",
				ModalDisplayName: "Interval (seconds)",
				Description:      "Seconds between captures (for record action, default: 5)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     5,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "duration",
				CLIName:          "duration",
				ModalDisplayName: "Duration (seconds)",
				Description:      "Total recording duration in seconds (for record action, default: 60, max: 600)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     60,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "max_frames",
				CLIName:          "max_frames",
				ModalDisplayName: "Max Frames",
				Description:      "Maximum number of frames to capture (for record action, default: 100)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     100,
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			interval, _ := taskData.Args.GetNumberArg("interval")
			duration, _ := taskData.Args.GetNumberArg("duration")
			msg := screenshotOPSECMessage(action, int(interval), int(duration))
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Screenshot captured. Screen capture API calls may be logged by EDR. Screenshot files are forensic evidence if not cleaned up. Rapid screenshots increase detection risk.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			if action == "record" {
				interval, _ := taskData.Args.GetNumberArg("interval")
				duration, _ := taskData.Args.GetNumberArg("duration")
				maxFrames, _ := taskData.Args.GetNumberArg("max_frames")
				display := fmt.Sprintf("Screen recording: %ds duration, %ds interval, max %d frames",
					int(duration), int(interval), int(maxFrames))
				response.DisplayParams = &display
				createArtifact(taskData.Task.ID, "API Call",
					fmt.Sprintf("Continuous screen capture (%ds @ %ds intervals)", int(duration), int(interval)))
			} else {
				display := "Screen capture"
				response.DisplayParams = &display
				createArtifact(taskData.Task.ID, "API Call",
					"Screen capture (platform-specific: GDI BitBlt on Windows, Xlib on Linux, CGDisplayCreateImage on macOS)")
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
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "File Write",
					ArtifactMessage:  fmt.Sprintf("Screenshot captured on %s", processResponse.TaskData.Callback.Host),
				})
				return response
			}
			if recordResult, ok := parseScreenshotRecordResult(responseText); ok {
				createArtifact(processResponse.TaskData.Task.ID, "File Write",
					fmt.Sprintf("Screen recording: %d frames over %s (stopped: %s)",
						recordResult.Frames, recordResult.Duration, recordResult.StoppedBy))
			} else if strings.Contains(responseText, "Screenshot captured") {
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "File Write",
					ArtifactMessage:  fmt.Sprintf("Screenshot captured on %s", processResponse.TaskData.Callback.Host),
				})
			}
			return response
		},
	})
}
