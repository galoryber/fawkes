package agentfunctions

import (
	"fmt"
	"strconv"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/MythicMeta/MythicContainer/rabbitmq"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "rpfwd",
		Description:         "Start or stop a reverse port forward. The agent listens on a local port; Mythic connects to the remote target.",
		HelpString:          "rpfwd start <port> <remote_ip> <remote_port>  /  rpfwd stop <port>",
		Version:             1,
		MitreAttackMappings: []string{"T1090"}, // Proxy
		SupportedUIFeatures: []string{},
		Author:              "@GlobeTechLLC",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Start or stop the reverse port forward",
				Choices:       []string{"start", "stop"},
				DefaultValue:  "start",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:            "start",
					},
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:            "stop",
					},
				},
			},
			{
				Name:          "port",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Local port for the agent to listen on",
				DefaultValue:  7000,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
						GroupName:            "start",
					},
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
						GroupName:            "stop",
					},
				},
			},
			{
				Name:          "remote_ip",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Remote IP to forward traffic to (accessible from Mythic server)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     3,
						GroupName:            "start",
					},
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "stop",
					},
				},
			},
			{
				Name:          "remote_port",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Remote port to forward traffic to",
				DefaultValue:  7000,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     4,
						GroupName:            "start",
					},
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "stop",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			// Support: rpfwd start 8080 10.0.0.1 80  /  rpfwd stop 8080
			parts := splitArgs(input)
			if len(parts) >= 1 {
				args.SetArgValue("action", parts[0])
			}
			if len(parts) >= 2 {
				if port, err := strconv.Atoi(parts[1]); err == nil {
					args.SetArgValue("port", port)
				}
			}
			if len(parts) >= 3 {
				args.SetArgValue("remote_ip", parts[2])
			}
			if len(parts) >= 4 {
				if port, err := strconv.Atoi(parts[3]); err == nil {
					args.SetArgValue("remote_port", port)
				}
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, err := taskData.Args.GetStringArg("action")
			if err != nil {
				logging.LogError(err, "Failed to get action arg")
				response.Error = err.Error()
				response.Success = false
				return response
			}

			port, err := taskData.Args.GetNumberArg("port")
			if err != nil {
				logging.LogError(err, "Failed to get port arg")
				response.Error = err.Error()
				response.Success = false
				return response
			}
			portInt := int(port)

			switch action {
			case "start":
				remoteIP, err := taskData.Args.GetStringArg("remote_ip")
				if err != nil {
					response.Error = err.Error()
					response.Success = false
					return response
				}
				remotePort, err := taskData.Args.GetNumberArg("remote_port")
				if err != nil {
					response.Error = err.Error()
					response.Success = false
					return response
				}
				remotePortInt := int(remotePort)

				displayParams := fmt.Sprintf("start on port %d → %s:%d", portInt, remoteIP, remotePortInt)
				response.DisplayParams = &displayParams

				proxyResp, err := mythicrpc.SendMythicRPCProxyStart(mythicrpc.MythicRPCProxyStartMessage{
					TaskID:     taskData.Task.ID,
					LocalPort:  portInt,
					RemotePort: remotePortInt,
					RemoteIP:   remoteIP,
					PortType:   string(rabbitmq.CALLBACK_PORT_TYPE_RPORTFWD),
				})
				if err != nil {
					logging.LogError(err, "Failed to start rpfwd proxy")
					response.Error = fmt.Sprintf("Failed to start rpfwd: %v", err)
					response.Success = false
					return response
				}
				if !proxyResp.Success {
					response.Error = fmt.Sprintf("rpfwd start failed: %s", proxyResp.Error)
					response.Success = false
					return response
				}

				// Remove remote params from agent task (agent only needs action + port)
				taskData.Args.RemoveArg("remote_port")
				taskData.Args.RemoveArg("remote_ip")
				taskData.Args.SetManualParameterGroup("start")

			case "stop":
				displayParams := fmt.Sprintf("stop on port %d", portInt)
				response.DisplayParams = &displayParams

				proxyResp, err := mythicrpc.SendMythicRPCProxyStop(mythicrpc.MythicRPCProxyStopMessage{
					TaskID:   taskData.Task.ID,
					Port:     portInt,
					PortType: string(rabbitmq.CALLBACK_PORT_TYPE_RPORTFWD),
				})
				if err != nil {
					logging.LogError(err, "Failed to stop rpfwd proxy")
					response.Error = fmt.Sprintf("Failed to stop rpfwd: %v", err)
					response.Success = false
					return response
				}
				if !proxyResp.Success {
					response.Error = fmt.Sprintf("rpfwd stop failed: %s", proxyResp.Error)
					response.Success = false
					return response
				}

			default:
				response.Error = fmt.Sprintf("Unknown action: %s", action)
				response.Success = false
			}

			return response
		},
	})
}
