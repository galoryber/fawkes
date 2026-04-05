package agentfunctions

import (
	"fmt"
	"regexp"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "pkg-list",
		Description:         "List installed packages and software. Enumerates dpkg/rpm/apk (Linux), Homebrew/Applications (macOS), or registry Uninstall keys (Windows). Supports filtering by name.",
		HelpString:          "pkg-list [-filter <substring>]",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1518"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "filter",
				CLIName:       "filter",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Case-insensitive substring filter on package/software name",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Listing installed packages/software (T1518). Software enumeration is a standard discovery technique. Low risk from API calls but querying package managers may generate process execution logs.",
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
			// Extract package count summary and notable security software
			// Look for count patterns like "(380 installed)" or "45 (3 matching)"
			countRe := regexp.MustCompile(`(\d+)\s+installed`)
			matches := countRe.FindStringSubmatch(responseText)
			total := "unknown"
			if matches != nil {
				total = matches[1]
			}
			// Determine platform from header
			platform := "Unknown"
			if strings.Contains(responseText, "Linux") {
				platform = "Linux"
			} else if strings.Contains(responseText, "macOS") {
				platform = "macOS"
			} else if strings.Contains(responseText, "Windows") {
				platform = "Windows"
			}
			createArtifact(processResponse.TaskData.Task.ID, "Software Discovery",
				fmt.Sprintf("Software inventory: %s packages on %s host", total, platform))
			// Flag notable security tools if present
			securityTools := []string{"defender", "crowdstrike", "sentinel", "falcon", "symantec",
				"mcafee", "sophos", "kaspersky", "eset", "malwarebytes", "carbon black", "carbonblack",
				"cylance", "tanium", "splunk", "osquery", "sysmon", "wireshark", "nmap", "metasploit"}
			lower := strings.ToLower(responseText)
			for _, tool := range securityTools {
				if strings.Contains(lower, tool) {
					createArtifact(processResponse.TaskData.Task.ID, "Software Discovery",
						fmt.Sprintf("Security tool detected: %s", tool))
				}
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
			filter, _ := taskData.Args.GetStringArg("filter")
			if filter != "" {
				display := fmt.Sprintf("Installed packages (filter: %s)", filter)
				response.DisplayParams = &display
			}
			return response
		},
	})
}
