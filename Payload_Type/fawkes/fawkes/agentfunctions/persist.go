package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "persist",
		Description:         "Install or remove persistence mechanisms (registry, startup folder, COM hijack, screensaver, IFEO, winlogon helper, print processor, accessibility features)",
		HelpString:          "persist -method <registry|startup-folder|com-hijack|screensaver|ifeo|winlogon|print-processor|accessibility|list> -action <install|remove> [-name <name>] [-path <exe_path>] [-hive <HKCU|HKLM>] [-clsid <CLSID>] [-timeout <seconds>]",
		Version:             4,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1547.001", "T1547.009", "T1546.015", "T1546.002", "T1546.012", "T1053.003", "T1543.002", "T1546.004", "T1098.004", "T1543.004", "T1070.009", "T1547.004", "T1547.012", "T1546.008"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
			CommandCanOnlyBeLoadedLater: true,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "method",
				ModalDisplayName: "Persistence Method",
				CLIName:          "method",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"registry", "startup-folder", "com-hijack", "screensaver", "ifeo", "winlogon", "print-processor", "accessibility", "crontab", "systemd", "shell-profile", "ssh-key", "launchagent", "list"},
				Description:      "Persistence method. Windows: registry, startup-folder, com-hijack, screensaver, ifeo, winlogon, print-processor, accessibility. Linux: crontab, systemd, shell-profile, ssh-key. macOS: launchagent. All: list.",
				DefaultValue:     "registry",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"install", "remove"},
				Description:      "Install or remove the persistence entry",
				DefaultValue:     "install",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "name",
				ModalDisplayName: "Entry Name",
				CLIName:          "name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Name for the persistence entry. Registry: value name. Startup: filename. IFEO/Accessibility: target exe (sethc.exe, utilman.exe). Winlogon: 'userinit' or 'shell'. Print-processor: processor name.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "Executable Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to the executable to persist. Defaults to the current agent binary.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "hive",
				ModalDisplayName: "Registry Hive",
				CLIName:          "hive",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"HKCU", "HKLM"},
				Description:      "Registry hive for Run key persistence (HKCU = current user, HKLM = all users, requires admin)",
				DefaultValue:     "HKCU",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "clsid",
				ModalDisplayName: "CLSID",
				CLIName:          "clsid",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "COM object CLSID to hijack (for com-hijack method). Default: {42aedc87-2188-41fd-b9a3-0c966feabec1} (MruPidlList, loaded by explorer.exe)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "timeout",
				ModalDisplayName: "Timeout (seconds)",
				CLIName:          "timeout",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Idle timeout in seconds before screensaver triggers (for screensaver method). Default: 60",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "schedule",
				ModalDisplayName: "Cron Schedule",
				CLIName:          "schedule",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Crontab schedule expression (Linux crontab method). Default: */5 * * * * (every 5 minutes)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "user",
				ModalDisplayName: "Target User",
				CLIName:          "user",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target user for persistence (Linux ssh-key method). Default: current user.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			method, _ := taskData.Args.GetStringArg("method")
			msg := fmt.Sprintf("OPSEC WARNING: Persistence operation (%s, method: %s). ", action, method)
			switch action {
			case "install":
				msg += "Creates persistent artifacts (registry keys, files, or scheduled tasks). " +
					"These survive reboots and may be detected by EDR baseline monitoring or autoruns analysis."
			case "remove":
				msg += "Removes persistence artifacts — cleanup operation."
			default:
				msg += "Querying persistence state — low detection risk."
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
			method, _ := taskData.Args.GetStringArg("method")
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    fmt.Sprintf("OPSEC AUDIT: Persistence %s (method: %s) configured. Artifacts will be created on execution.", action, method),
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
			method, _ := taskData.Args.GetStringArg("method")
			action, _ := taskData.Args.GetStringArg("action")
			name, _ := taskData.Args.GetStringArg("name")
			display := fmt.Sprintf("%s %s", action, method)
			response.DisplayParams = &display
			if action == "install" {
				switch method {
				case "registry":
					hive, _ := taskData.Args.GetStringArg("hive")
					createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\%s", hive, name))
				case "startup-folder":
					createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("Startup folder: %s", name))
				case "com-hijack":
					clsid, _ := taskData.Args.GetStringArg("clsid")
					if clsid == "" {
						clsid = "{42aedc87-2188-41fd-b9a3-0c966feabec1}"
					}
					path, _ := taskData.Args.GetStringArg("path")
					createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("HKCU\\Software\\Classes\\CLSID\\%s\\InprocServer32 = %s", clsid, path))
				case "screensaver":
					path, _ := taskData.Args.GetStringArg("path")
					createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE = %s", path))
				case "ifeo":
					path, _ := taskData.Args.GetStringArg("path")
					createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s\\Debugger = %s", name, path))
				case "winlogon":
					path, _ := taskData.Args.GetStringArg("path")
					target := name
					if target == "" {
						target = "Userinit"
					}
					createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\%s (appended %s)", target, path))
				case "print-processor":
					path, _ := taskData.Args.GetStringArg("path")
					procName := name
					if procName == "" {
						procName = "FawkesProc"
					}
					createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("Print processor DLL: C:\\Windows\\System32\\spool\\prtprocs\\x64\\%s", path))
					createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("HKLM\\...\\Print Processors\\%s\\Driver", procName))
				case "accessibility":
					path, _ := taskData.Args.GetStringArg("path")
					target := name
					if target == "" {
						target = "sethc.exe"
					}
					createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("Replaced C:\\Windows\\System32\\%s with %s", target, path))
				}
			}
			if action == "install" || action == "remove" {
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[PERSIST] persist %s %s (%s) on %s", action, method, name, taskData.Callback.Host), true)
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
				return response
			}
			method, _ := processResponse.TaskData.Args.GetStringArg("method")
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			if action == "install" && strings.Contains(responseText, "Installed") {
				desc := fmt.Sprintf("[Persistence Installed] method: %s", method)
				if name, _ := processResponse.TaskData.Args.GetStringArg("name"); name != "" {
					desc += ", name: " + name
				}
				createArtifact(processResponse.TaskData.Task.ID, "Persistence Mechanism", desc)
			} else if method == "list" || action == "" {
				// Track discovered persistence entries from enumeration
				lines := strings.Split(responseText, "\n")
				for _, line := range lines {
					trimmed := strings.TrimSpace(line)
					if strings.HasPrefix(trimmed, "- ") || (strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "Key:") && !strings.HasPrefix(trimmed, "HKCU") && !strings.HasPrefix(trimmed, "HKLM")) {
						continue
					}
					// Track run key entries and startup folder entries
					if strings.Contains(trimmed, "Run\\") || strings.Contains(trimmed, "Startup") && strings.Contains(trimmed, ":") {
						createArtifact(processResponse.TaskData.Task.ID, "Persistence Mechanism", "[Persist Enum] "+trimmed)
					}
				}
			}
			return response
		},
	})
}
