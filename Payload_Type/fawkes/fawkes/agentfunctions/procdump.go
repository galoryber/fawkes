package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "procdump",
		Description:         "Dump process memory. Windows: MiniDumpWriteDump (lsass auto-discovery or any PID). Linux: /proc/<pid>/mem with maps-based region dumping. Dumps are uploaded to Mythic and cleaned from disk.",
		HelpString:          "procdump\nprocdump -action lsass\nprocdump -action dump -pid 1234\nprocdump -action search  (Linux: find credential-holding processes)",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.001", "T1003.007"}, // OS Credential Dumping: LSASS Memory + Proc Filesystem
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "Dump type: lsass (Windows: auto-find lsass.exe), dump (dump process by PID), search (Linux: find credential-holding processes)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"lsass", "dump", "search"},
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: "
			switch action {
			case "lsass", "":
				msg += "Dumping lsass.exe process memory. This touches LSASS — heavily monitored by EDR/AV. " +
					"May trigger Credential Guard, RunAsPPL, or CrowdStrike/Defender alerts. " +
					"Creates a minidump file on disk (cleaned after upload)."
			case "dump":
				pid, _ := taskData.Args.GetNumberArg("pid")
				msg += fmt.Sprintf("Dumping process memory (PID %d). "+
					"Creates a minidump file on disk (cleaned after upload). "+
					"MiniDumpWriteDump API call may be flagged by EDR.", int(pid))
			default:
				msg += "Process memory search — enumerates processes for credential-holding targets."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC AUDIT: Process dump "
			if action == "lsass" || action == "" {
				msg += "(lsass) configured. MiniDumpWriteDump artifacts will be created."
			} else if action == "dump" {
				pid, _ := taskData.Args.GetNumberArg("pid")
				msg += fmt.Sprintf("(PID %d) configured. MiniDumpWriteDump artifacts will be created.", int(pid))
			} else {
				msg += "search configured. Process enumeration will occur."
			}
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			switch action {
			case "dump":
				if pid > 0 {
					displayMsg = fmt.Sprintf("Dump PID %d", int(pid))
				} else {
					displayMsg = "Dump (PID required)"
				}
			case "search":
				displayMsg = "Search for credential-holding processes"
			default:
				displayMsg = "Dump lsass.exe"
			}
			response.DisplayParams = &displayMsg

			if action != "search" {
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("Process memory dump — %s", displayMsg))
			}

			return response
		},
	})
}
