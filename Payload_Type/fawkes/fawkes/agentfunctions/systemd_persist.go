package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "systemd-persist",
		Description:         "Install, remove, or list systemd service persistence. Creates user or system service units that restart on failure and persist across reboots.",
		HelpString:          "systemd-persist -action install -name backdoor -exec_start /tmp/payload\nsystemd-persist -action list\nsystemd-persist -action remove -name backdoor",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1543.002"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_LINUX,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "install: create systemd service, remove: delete service, list: enumerate services",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"install", "remove", "list"},
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "name",
				CLIName:          "name",
				ModalDisplayName: "Service Name",
				Description:      "Unit name (without .service suffix)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "exec_start",
				CLIName:          "exec_start",
				ModalDisplayName: "ExecStart",
				Description:      "Command to execute (full path recommended)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "description",
				CLIName:          "description",
				ModalDisplayName: "Description",
				Description:      "Service description (visible in systemctl output)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "system",
				CLIName:          "system",
				ModalDisplayName: "System Service",
				Description:      "true: install as system service (/etc/systemd/system), false: user service (~/.config/systemd/user)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "restart_sec",
				CLIName:          "restart_sec",
				ModalDisplayName: "Restart Delay (sec)",
				Description:      "Seconds to wait before restarting on failure (default 10)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     10,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timer",
				CLIName:          "timer",
				ModalDisplayName: "Timer Schedule",
				Description:      "Optional systemd timer OnCalendar spec (e.g., '*-*-* *:00/5:00' for every 5 min). Creates a .timer unit alongside the service.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
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
			name, _ := taskData.Args.GetStringArg("name")

			var displayMsg string
			switch action {
			case "install":
				execStart, _ := taskData.Args.GetStringArg("exec_start")
				displayMsg = fmt.Sprintf("systemd-persist install '%s' (exec: %s)", name, execStart)
			case "remove":
				displayMsg = fmt.Sprintf("systemd-persist remove '%s'", name)
			default:
				displayMsg = "systemd-persist list"
			}
			response.DisplayParams = &displayMsg

			artifactType := "File Create"
			artifactMsg := fmt.Sprintf("Systemd service: %s", action)
			if action == "install" {
				artifactMsg = fmt.Sprintf("Systemd service install: %s.service", name)
			} else if action == "remove" {
				artifactType = "File Delete"
				artifactMsg = fmt.Sprintf("Systemd service remove: %s.service", name)
			}

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: artifactType,
				ArtifactMessage:  artifactMsg,
			})

			return response
		},
	})
}
