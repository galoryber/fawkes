package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "klist",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "klist_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Enumerate cached Kerberos tickets — list, purge, dump, or import tickets for pass-the-ticket (T1550.003)",
		HelpString:          "klist\nklist -action list\nklist -action list -server krbtgt\nklist -action purge\nklist -action dump -server krbtgt/DOMAIN.LOCAL\nklist -action import -ticket <base64>",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1558", "T1550.003"},
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
				Description:      "Action to perform: list (enumerate tickets), purge (clear cache), dump (export ticket data), import (inject ticket for pass-the-ticket)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"list", "purge", "dump", "import"},
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "server",
				CLIName:          "server",
				ModalDisplayName: "Server Filter",
				Description:      "Filter by server name (list) or target SPN for dump (e.g., krbtgt/DOMAIN.LOCAL)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "ticket",
				CLIName:          "ticket",
				ModalDisplayName: "Ticket Data",
				Description:      "Base64-encoded ticket data for import action (kirbi on Windows, ccache on Linux/macOS)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "Output Path",
				Description:      "Output path for import action (Linux/macOS only, default: /tmp/krb5cc_<uid>)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")
			ticket, _ := taskData.Args.GetStringArg("ticket")

			displayMsg := fmt.Sprintf("klist %s", action)
			if server != "" {
				displayMsg += fmt.Sprintf(" (server=%s)", server)
			}
			if action == "import" && ticket != "" {
				ticketPreview := ticket
				if len(ticketPreview) > 20 {
					ticketPreview = ticketPreview[:20] + "..."
				}
				displayMsg += fmt.Sprintf(" (ticket=%s)", ticketPreview)
			}
			response.DisplayParams = &displayMsg

			artifactMsg := fmt.Sprintf("Kerberos ticket cache %s", action)
			if action == "import" {
				artifactMsg = "Kerberos ticket injection (Pass-the-Ticket)"
			}
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  artifactMsg,
			})

			return response
		},
	})
}
