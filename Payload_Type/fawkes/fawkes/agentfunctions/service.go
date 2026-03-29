package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "service",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "service_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Manage services — Windows via SCM API, Linux via systemctl, macOS via launchctl. Query, start, stop, restart, create, delete, list, enable, disable.",
		HelpString:          "service -action <query|start|stop|restart|create|delete|list|enable|disable> -name <service_name> [-binpath <path>] [-display <name>] [-start <auto|demand|disabled>]",
		Version:             5,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1543.002", "T1543.003", "T1543.004", "T1562.001"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"query", "start", "stop", "restart", "create", "delete", "list", "enable", "disable"},
				Description:      "Action to perform on the service",
				DefaultValue:     "query",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "name",
				ModalDisplayName: "Service Name",
				CLIName:          "name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Service name/label (Windows: Spooler; Linux: sshd; macOS: com.apple.ssh)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "binpath",
				ModalDisplayName: "Binary Path",
				CLIName:          "binpath",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to the service binary (required for create)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "display",
				ModalDisplayName: "Display Name",
				CLIName:          "display",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Display name for the service (optional, for create)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "start",
				ModalDisplayName: "Start Type",
				CLIName:          "start",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"demand", "auto", "disabled"},
				Description:      "Service start type: demand (manual), auto (automatic), disabled",
				DefaultValue:     "demand",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			name, _ := taskData.Args.GetStringArg("name")
			msg := fmt.Sprintf("OPSEC WARNING: Service operation (%s", action)
			if name != "" {
				msg += fmt.Sprintf(", name: %s", name)
			}
			msg += "). "
			switch action {
			case "create":
				msg += "Creates a Windows service — generates Event ID 7045 (System) and 4697 (Security). " +
					"Service creation is a classic persistence/lateral movement indicator."
			case "start", "stop":
				msg += "Starting/stopping a service — generates Event ID 7036. May impact system stability."
			case "delete":
				msg += "Deletes a Windows service — cleanup operation."
			default:
				msg += "Querying service state — low detection risk."
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
			name, _ := taskData.Args.GetStringArg("name")
			msg := fmt.Sprintf("OPSEC AUDIT: Service %s", action)
			if name != "" {
				msg += fmt.Sprintf(" (name: %s)", name)
			}
			msg += " configured. SCM/Event Log artifacts will be created."
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
			name, _ := taskData.Args.GetStringArg("name")
			if name != "" {
				display := fmt.Sprintf("%s %s", action, name)
				response.DisplayParams = &display
			} else {
				display := fmt.Sprintf("%s", action)
				response.DisplayParams = &display
			}
			if taskData.Callback.OS == "Linux" {
				// Linux: systemctl artifacts
				switch action {
				case "list":
					createArtifact(taskData.Task.ID, "Process Create", "systemctl list-units --type=service --all")
				case "query":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("systemctl show %s.service", name))
				case "start", "stop", "restart", "enable", "disable":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("systemctl %s %s.service", action, name))
				case "create":
					binpath, _ := taskData.Args.GetStringArg("binpath")
					createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("/etc/systemd/system/%s.service (ExecStart=%s)", name, binpath))
					createArtifact(taskData.Task.ID, "Process Create", "systemctl daemon-reload")
				case "delete":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("systemctl stop %s.service", name))
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("systemctl disable %s.service", name))
					createArtifact(taskData.Task.ID, "File Delete", fmt.Sprintf("/etc/systemd/system/%s.service", name))
					createArtifact(taskData.Task.ID, "Process Create", "systemctl daemon-reload")
				}
			} else if taskData.Callback.OS == "macOS" {
				// macOS: launchctl artifacts
				switch action {
				case "list":
					createArtifact(taskData.Task.ID, "Process Create", "launchctl list")
				case "query":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("launchctl print system/%s", name))
				case "start":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("launchctl kickstart system/%s", name))
				case "restart":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("launchctl kickstart -k system/%s", name))
				case "stop":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("launchctl kill SIGTERM system/%s", name))
				case "enable":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("launchctl enable system/%s", name))
				case "disable":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("launchctl disable system/%s", name))
				case "create":
					binpath, _ := taskData.Args.GetStringArg("binpath")
					createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("%s.plist (Program=%s)", name, binpath))
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("launchctl load %s.plist", name))
				case "delete":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("launchctl unload %s.plist", name))
					createArtifact(taskData.Task.ID, "File Delete", fmt.Sprintf("%s.plist", name))
				}
			} else {
				// Windows: SCM API artifacts
				switch action {
				case "create":
					binpath, _ := taskData.Args.GetStringArg("binpath")
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM CreateService %s binpath=%q", name, binpath))
				case "start":
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM StartService %s", name))
				case "stop":
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM ControlService(Stop) %s", name))
				case "restart":
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM ControlService(Stop) %s", name))
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM StartService %s", name))
				case "delete":
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM DeleteService %s", name))
				case "enable":
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM ChangeServiceConfig(%s, StartType=Automatic)", name))
				case "disable":
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM ChangeServiceConfig(%s, StartType=Disabled)", name))
				}
			}
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
