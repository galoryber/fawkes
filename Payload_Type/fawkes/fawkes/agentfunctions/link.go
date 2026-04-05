package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "link",
		Description:         "Link to a P2P agent via TCP or named pipe to establish a peer-to-peer connection for internal pivoting. The target agent must be built with a TCP or named pipe profile and listening.",
		HelpString:          "link -host <ip> -port <port> | link -connection_type namedpipe -host <ip> -pipe_name <name>",
		Version:             1,
		MitreAttackMappings: []string{"T1572"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "connection_type",
				CLIName:          "connection_type",
				ModalDisplayName: "Connection Type",
				Description:      "P2P transport: tcp (default) or namedpipe (Windows, uses SMB port 445)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"tcp", "namedpipe"},
				DefaultValue:     "tcp",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "host",
				CLIName:          "host",
				ModalDisplayName: "Target Host",
				Description:      "IP address or hostname of the target P2P agent",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "Target Port",
				Description:      "TCP port the target P2P agent is listening on (TCP mode only)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     7777,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "pipe_name",
				CLIName:          "pipe_name",
				ModalDisplayName: "Pipe Name",
				Description:      "Named pipe name without \\\\.\\ prefix (e.g., msrpc-f9a1). Used when connection_type is namedpipe.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
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
			host, _ := taskData.Args.GetStringArg("host")
			connType, _ := taskData.Args.GetStringArg("connection_type")
			if connType == "" {
				connType = "tcp"
			}

			var msg string
			switch connType {
			case "namedpipe":
				pipeName, _ := taskData.Args.GetStringArg("pipe_name")
				msg = fmt.Sprintf("OPSEC WARNING: Linking to P2P agent at %s via named pipe '%s'. "+
					"Named pipe connections use SMB (port 445) which blends with normal Windows traffic. "+
					"However, named pipe access generates ETW events (Microsoft-Windows-SMBClient) and "+
					"Sysmon Event ID 17/18 (PipeEvent) if configured.", host, pipeName)
			default:
				msg = fmt.Sprintf("OPSEC WARNING: Linking to P2P agent at %s via TCP. "+
					"TCP connection establishment generates network telemetry. "+
					"Firewall rules and network monitoring may detect the lateral connection.", host)
			}

			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			host, _ := taskData.Args.GetStringArg("host")
			connType, _ := taskData.Args.GetStringArg("connection_type")
			if connType == "" {
				connType = "tcp"
			}

			var display string
			var artifact string
			switch connType {
			case "namedpipe":
				pipeName, _ := taskData.Args.GetStringArg("pipe_name")
				display = fmt.Sprintf(`\\%s\pipe\%s`, host, pipeName)
				artifact = fmt.Sprintf("Named pipe connect to \\\\%s\\pipe\\%s for P2P linking (SMB port 445)", host, pipeName)
			default:
				port, _ := taskData.Args.GetNumberArg("port")
				display = fmt.Sprintf("%s:%d", host, int(port))
				artifact = "TCP connect to P2P agent for peer-to-peer linking"
			}
			response.DisplayParams = &display

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  artifact,
			})

			return response
		},
	})
}
