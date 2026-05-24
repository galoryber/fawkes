package agentfunctions

import (
	"encoding/json"
	"fmt"
	"strings"

	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "start-clr",
		Description:         "Initialize .NET CLR runtime or execute assemblies with auto AMSI/ETW patching. Use -action execute-assembly for single-command assembly execution (like Cobalt Strike's execute-assembly).",
		HelpString:          "start-clr                                           # Init CLR only\nstart-clr -action execute-assembly -assembly <b64>   # Execute assembly with auto-patching\nstart-clr -action execute-assembly -assembly <b64> -arguments 'arg1 arg2'",
		Version:             3,
		MitreAttackMappings: []string{"T1055.001", "T1620", "T1562.001"},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "startclr_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Action: init (default, initialize CLR with optional patching) or execute-assembly (single-command assembly execution with auto AMSI+ETW patching)",
				Choices:       []string{"init", "execute-assembly"},
				DefaultValue:  "init",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, UIModalPosition: 0, GroupName: "Default"},
				},
			},
			{
				Name:          "assembly",
				CLIName:       "assembly",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Base64-encoded .NET assembly bytes (for execute-assembly action)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, UIModalPosition: 5, GroupName: "Default"},
				},
			},
			{
				Name:          "arguments",
				CLIName:       "arguments",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Arguments to pass to the assembly's Main() method (for execute-assembly action)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, UIModalPosition: 6, GroupName: "Default"},
				},
			},
			{
				Name:             "amsi_patch",
				ModalDisplayName: "AMSI Patch Method",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Method to patch AMSI (AmsiScanBuffer). Ret Patch writes 0xC3 at function entry. Autopatch writes a JMP-to-RET. Hardware Breakpoint uses debug registers + VEH (experimental).",
				Choices:          []string{"None", "Ret Patch", "Autopatch", "Hardware Breakpoint"},
				DefaultValue:     "None",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "etw_patch",
				ModalDisplayName: "ETW Patch Method",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Method to patch ETW (EtwEventWrite). Ret Patch writes 0xC3 at function entry. Autopatch writes a JMP-to-RET. Hardware Breakpoint uses debug registers + VEH (experimental).",
				Choices:          []string{"None", "Ret Patch", "Autopatch", "Hardware Breakpoint"},
				DefaultValue:     "None",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// Accept empty input for backward compat (defaults to None/None)
			if input == "" {
				return nil
			}
			return args.LoadArgsFromJSONString(input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			amsiPatch, _ := taskData.Args.GetStringArg("amsi_patch")
			etwPatch, _ := taskData.Args.GetStringArg("etw_patch")
			msg := "OPSEC WARNING: Initializing .NET CLR runtime in-process."
			if amsiPatch != "None" && amsiPatch != "" {
				msg += fmt.Sprintf(" AMSI patch (%s) modifies amsi.dll in memory — may trigger tamper detection.", amsiPatch)
			}
			if etwPatch != "None" && etwPatch != "" {
				msg += fmt.Sprintf(" ETW patch (%s) modifies ntdll.dll — may trigger integrity monitoring.", etwPatch)
			}
			msg += " CLR loading generates ETW events and may be monitored by .NET-aware EDR."
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
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
				OpsecPostMessage:    "OPSEC AUDIT: CLR runtime initialized. Loading .NET runtime into an unmanaged process is a known attack indicator. AMSI hooks are activated on CLR load. ETW events generated.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			if action == "" {
				action = "init"
			}

			amsiPatch, err := taskData.Args.GetStringArg("amsi_patch")
			if err != nil {
				logging.LogError(err, "Failed to get amsi_patch arg, defaulting to None")
				amsiPatch = "None"
			}

			etwPatch, err := taskData.Args.GetStringArg("etw_patch")
			if err != nil {
				logging.LogError(err, "Failed to get etw_patch arg, defaulting to None")
				etwPatch = "None"
			}

			var displayParams string
			if action == "execute-assembly" {
				arguments, _ := taskData.Args.GetStringArg("arguments")
				if arguments != "" {
					displayParams = fmt.Sprintf("execute-assembly (args: %s)", arguments)
				} else {
					displayParams = "execute-assembly"
				}
			} else {
				displayParams = fmt.Sprintf("CLR Init | AMSI: %s | ETW: %s", amsiPatch, etwPatch)
			}
			response.DisplayParams = &displayParams

			params := map[string]interface{}{
				"action":     action,
				"amsi_patch": amsiPatch,
				"etw_patch":  etwPatch,
			}
			if action == "execute-assembly" {
				assembly, _ := taskData.Args.GetStringArg("assembly")
				arguments, _ := taskData.Args.GetStringArg("arguments")
				params["assembly"] = assembly
				params["arguments"] = arguments
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			taskData.Args.SetManualArgs(string(paramsJSON))
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
			if strings.Contains(responseText, "success") || strings.Contains(responseText, "Success") || strings.Contains(responseText, "CLR") || strings.Contains(responseText, "loaded") {
				l := len(responseText)
				if l > 200 {
					l = 200
				}
				createArtifact(processResponse.TaskData.Task.ID, "Process Injection", fmt.Sprintf("[start-clr] %s", responseText[:l]))
			}
			return response
		},
	})
}
