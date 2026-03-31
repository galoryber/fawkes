package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "persist-enum",
		Description:         "Enumerate persistence mechanisms — Windows: registry, startup, tasks, services. Linux: cron, systemd, shell profiles, SSH keys, udev rules, kernel modules, motd, at jobs, D-Bus services, PAM modules, package hooks, logrotate, NetworkManager, anacron. macOS: LaunchAgents, login items, periodic scripts, auth plugins, emond, at jobs, SSH keys.",
		HelpString:          "persist-enum -category all\n\nCategories by platform:\n  Windows: all, registry, startup, winlogon, ifeo, appinit, tasks, services\n  Linux: all, cron, systemd, shell, startup, ssh, preload, udev, modules, motd, at, dbus, pam, packages, logrotate, networkmanager, anacron\n  macOS: all, launchd, cron, shell, login, periodic, authplugins, emond, at, ssh",
		Version:             6,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1547", "T1547.002", "T1547.006", "T1546", "T1546.014", "T1053", "T1543", "T1098.004", "T1556.003"}, // Boot/Logon Autostart, Auth Plugins, Kernel Modules, Event Triggered, Emond, Scheduled Task, Create/Modify System Process, SSH Authorized Keys, Modify Authentication Process: PAM
		SupportedUIFeatures: []string{},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "persist_enum_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "category",
				CLIName:          "category",
				ModalDisplayName: "Category",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Which persistence category to enumerate (default: all). Platform-specific categories — see help.",
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				input = "{}"
			}
			return args.LoadArgsFromJSONString(input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Enumerates persistence mechanisms across registry run keys, scheduled tasks, services, cron jobs, LaunchAgents, and SSH keys (T1547, T1053, T1543, T1098.004). Extensive registry/filesystem access patterns are monitored by EDR.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			sectionRe := regexp.MustCompile(`^---\s+(.+?)\s+---`)
			currentSection := ""
			for _, line := range strings.Split(responseText, "\n") {
				if m := sectionRe.FindStringSubmatch(line); m != nil {
					currentSection = m[1]
					continue
				}
				if currentSection == "" {
					continue
				}
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "===") || strings.HasPrefix(trimmed, "---") {
					continue
				}
				// Skip empty-result indicators like "(none found)", "(all defaults)", etc.
				if strings.HasPrefix(trimmed, "(") {
					continue
				}
				createArtifact(processResponse.TaskData.Task.ID, "Persistence Mechanism",
					fmt.Sprintf("[%s] %s", currentSection, trimmed))
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			category, _ := taskData.Args.GetStringArg("category")
			if category == "" {
				category = "all"
			}
			displayParams := "category: " + category
			response.DisplayParams = &displayParams

			return response
		},
	})
}
