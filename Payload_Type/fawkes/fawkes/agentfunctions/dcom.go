package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "dcom",
		Description:         "Execute commands on remote hosts via DCOM lateral movement. Supports MMC20.Application, ShellWindows, and ShellBrowserWindow objects.",
		HelpString:          "dcom -action exec -host <target> -command <cmd> [-args <arguments>] [-object mmc20|shellwindows|shellbrowser] [-dir <directory>] [-username <user> -password <pass> -domain <domain>]",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1021.003"}, // Remote Services: Distributed Component Object Model
		SupportedUIFeatures: []string{},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "dcom_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:                []string{agentstructs.SUPPORTED_OS_WINDOWS},
			CommandCanOnlyBeLoadedLater: true,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"exec"},
				DefaultValue:  "exec",
				Description:   "Action to perform",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "host",
				CLIName:              "host",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				Description:          "Target hostname or IP address",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "object",
				CLIName:       "object",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"mmc20", "shellwindows", "shellbrowser"},
				DefaultValue:  "mmc20",
				Description:   "DCOM object: MMC20.Application (most reliable), ShellWindows (requires explorer.exe), ShellBrowserWindow",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "command",
				CLIName:       "command",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Command or program to execute (e.g., 'cmd.exe', 'powershell.exe', path to payload)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     4,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "args",
				CLIName:       "args",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Arguments to pass to the command (e.g., '/c whoami > C:\\output.txt')",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "dir",
				CLIName:       "dir",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Working directory on the target (default: C:\\Windows\\System32)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     6,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "username",
				CLIName:       "username",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Username for DCOM auth (optional — uses make-token credentials if not specified)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     7,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "password",
				CLIName:       "password",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Password for DCOM auth (optional — uses make-token credentials if not specified)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     8,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "domain",
				CLIName:       "domain",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Domain for DCOM auth (optional — uses make-token credentials if not specified)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     9,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Operation timeout in seconds (default: 120). Prevents agent hangs on unreachable targets.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     120,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     10,
						GroupName:           "Default",
					},
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
			host, _ := taskData.Args.GetStringArg("host")
			action, _ := taskData.Args.GetStringArg("action")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: DCOM lateral movement to %s (action: %s). Creates remote COM object via RPC/TCP 135. Generates network connections, DCOM launch events (Event ID 10016), and process creation on the remote host. Detectable by monitoring RPC traffic and unusual DCOM object instantiation.", host, action),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: DCOM lateral movement completed. Generates Event ID 4624 (logon type 3) on remote host. DCOM traffic uses dynamic RPC ports (TCP 49152+). The COM object used (MMC20/ShellWindows/ShellBrowserWindow) may be logged by process creation monitoring.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			// Parse: DCOM <Object> executed on <host>:
			re := regexp.MustCompile(`DCOM\s+(\S+)\s+executed on\s+(\S+?):`)
			if m := re.FindStringSubmatch(responseText); len(m) > 2 {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("DCOM execution: %s on %s", m[1], m[2]))
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			host, _ := taskData.Args.GetStringArg("host")
			command, _ := taskData.Args.GetStringArg("command")
			object, _ := taskData.Args.GetStringArg("object")
			display := fmt.Sprintf("%s via %s", host, object)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("DCOM CoCreateInstanceEx %s on %s: %s", object, host, command))
			logOperationEvent(taskData.Task.ID,
				fmt.Sprintf("[LATERAL] dcom: remote execution via %s on %s from %s", object, host, taskData.Callback.Host), true)
			return response
		},
	})
}
