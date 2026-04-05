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
		Description:         "Start, stop, or forward port forwarding through this agent. 'start' creates a reverse port forward (agent listens, Mythic connects to remote). 'forward' creates a local relay (agent listens, agent connects to internal target).",
		HelpString:          "rpfwd start <port> <remote_ip> <remote_port>  /  rpfwd forward <port> <target_ip> <target_port>  /  rpfwd stop <port>",
		Version:             2,
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
				Description:   "start = reverse port forward (Mythic connects to remote target), forward = local relay (agent connects to internal target), stop = stop forwarding",
				Choices:       []string{"start", "forward", "stop"},
				DefaultValue:  "start",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
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
					},
				},
			},
			{
				Name:          "remote_ip",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Remote IP to forward traffic to (for 'start': accessible from Mythic server)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
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
						ParameterIsRequired: false,
						UIModalPosition:     4,
					},
				},
			},
			{
				Name:          "target_ip",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Internal target IP (for 'forward': accessible from the agent's host)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
					},
				},
			},
			{
				Name:          "target_port",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Internal target port (for 'forward')",
				DefaultValue:  0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     6,
					},
				},
			},
			{
				Name:          "bind_address",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Bind address for the local listener (default: 0.0.0.0, use 127.0.0.1 to restrict to localhost)",
				DefaultValue:  "0.0.0.0",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     7,
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			// Support:
			//   rpfwd start 8080 10.0.0.1 80
			//   rpfwd forward 8080 10.0.0.1 80
			//   rpfwd forward 8080 10.0.0.1 80 127.0.0.1
			//   rpfwd stop 8080
			parts := splitArgs(input)
			if len(parts) >= 1 {
				args.SetArgValue("action", parts[0])
			}
			if len(parts) >= 2 {
				if port, err := strconv.Atoi(parts[1]); err == nil {
					args.SetArgValue("port", port)
				}
			}
			action := ""
			if len(parts) >= 1 {
				action = parts[0]
			}
			if action == "forward" {
				if len(parts) >= 3 {
					args.SetArgValue("target_ip", parts[2])
				}
				if len(parts) >= 4 {
					if port, err := strconv.Atoi(parts[3]); err == nil {
						args.SetArgValue("target_port", port)
					}
				}
				if len(parts) >= 5 {
					args.SetArgValue("bind_address", parts[4])
				}
			} else {
				if len(parts) >= 3 {
					args.SetArgValue("remote_ip", parts[2])
				}
				if len(parts) >= 4 {
					if port, err := strconv.Atoi(parts[3]); err == nil {
						args.SetArgValue("remote_port", port)
					}
				}
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: Port forward operation (T1090). "
			switch action {
			case "forward":
				msg += "Agent will listen on a local port AND connect to an internal target. Creates detectable listening port and outbound connections. Network monitoring may detect the relay pattern."
			case "start":
				msg += "Agent will listen on a local port and tunnel traffic through C2. Network monitoring may detect unexpected listening ports and tunnel traffic patterns."
			default:
				msg += "Stopping port forward — listener and connections will be closed."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
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
				if err != nil || remoteIP == "" {
					response.Error = "remote_ip is required for start action"
					response.Success = false
					return response
				}
				remotePort, err := taskData.Args.GetNumberArg("remote_port")
				if err != nil {
					response.Error = "remote_port is required for start action"
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

			case "forward":
				targetIP, err := taskData.Args.GetStringArg("target_ip")
				if err != nil || targetIP == "" {
					response.Error = "target_ip is required for forward action"
					response.Success = false
					return response
				}
				targetPort, err := taskData.Args.GetNumberArg("target_port")
				if err != nil || targetPort == 0 {
					response.Error = "target_port is required for forward action"
					response.Success = false
					return response
				}
				targetPortInt := int(targetPort)

				bindAddr, _ := taskData.Args.GetStringArg("bind_address")
				if bindAddr == "" {
					bindAddr = "0.0.0.0"
				}

				displayParams := fmt.Sprintf("forward %s:%d → %s:%d (bind %s)", bindAddr, portInt, targetIP, targetPortInt, bindAddr)
				response.DisplayParams = &displayParams

				// Register with Mythic for UI tracking using rpfwd type.
				// The agent handles the target connection locally — Mythic tracks the entry.
				proxyResp, err := mythicrpc.SendMythicRPCProxyStart(mythicrpc.MythicRPCProxyStartMessage{
					TaskID:     taskData.Task.ID,
					LocalPort:  portInt,
					RemotePort: targetPortInt,
					RemoteIP:   targetIP,
					PortType:   string(rabbitmq.CALLBACK_PORT_TYPE_RPORTFWD),
				})
				if err != nil {
					logging.LogError(err, "Failed to register forward proxy")
					response.Error = fmt.Sprintf("Failed to register forward: %v", err)
					response.Success = false
					return response
				}
				if !proxyResp.Success {
					response.Error = fmt.Sprintf("Forward registration failed: %s", proxyResp.Error)
					response.Success = false
					return response
				}

				// Keep target params in agent task — agent needs them to connect
				// Remove remote params if set (avoid confusion)
				taskData.Args.RemoveArg("remote_port")
				taskData.Args.RemoveArg("remote_ip")

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
