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
		Name:                "socks",
		Description:         "Start or stop a SOCKS5 proxy through this callback",
		HelpString:          "socks start [port]  /  socks stop [port]",
		Version:             1,
		MitreAttackMappings: []string{"T1090"}, // Proxy
		SupportedUIFeatures: []string{},
		Author:              "@xorrior",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Start or stop the SOCKS proxy",
				Choices:       []string{"start", "stop"},
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
				Description:   "Port for Mythic to listen on",
				DefaultValue:  7000,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// Support: socks start 1080  /  socks stop 1080  /  socks start  /  socks stop
			if input == "" {
				return nil
			}
			parts := splitArgs(input)
			if len(parts) >= 1 {
				args.SetArgValue("action", parts[0])
			}
			if len(parts) >= 2 {
				if port, err := strconv.Atoi(parts[1]); err == nil {
					args.SetArgValue("port", port)
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

			displayParams := fmt.Sprintf("%s %d", action, portInt)
			response.DisplayParams = &displayParams

			switch action {
			case "start":
				proxyResp, err := mythicrpc.SendMythicRPCProxyStart(mythicrpc.MythicRPCProxyStartMessage{
					TaskID:    taskData.Task.ID,
					LocalPort: portInt,
					PortType:  string(rabbitmq.CALLBACK_PORT_TYPE_SOCKS),
				})
				if err != nil {
					logging.LogError(err, "Failed to start SOCKS proxy")
					response.Error = fmt.Sprintf("Failed to start SOCKS proxy: %v", err)
					response.Success = false
					return response
				}
				if !proxyResp.Success {
					response.Error = fmt.Sprintf("SOCKS proxy start failed: %s", proxyResp.Error)
					response.Success = false
					return response
				}

			case "stop":
				proxyResp, err := mythicrpc.SendMythicRPCProxyStop(mythicrpc.MythicRPCProxyStopMessage{
					TaskID:   taskData.Task.ID,
					Port:     portInt,
					PortType: string(rabbitmq.CALLBACK_PORT_TYPE_SOCKS),
				})
				if err != nil {
					logging.LogError(err, "Failed to stop SOCKS proxy")
					response.Error = fmt.Sprintf("Failed to stop SOCKS proxy: %v", err)
					response.Success = false
					return response
				}
				if !proxyResp.Success {
					response.Error = fmt.Sprintf("SOCKS proxy stop failed: %s", proxyResp.Error)
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

// splitArgs splits a command string on whitespace, respecting quotes
func splitArgs(input string) []string {
	var args []string
	var current []byte
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(input); i++ {
		c := input[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current = append(current, c)
			}
		} else if c == '"' || c == '\'' {
			inQuote = true
			quoteChar = c
		} else if c == ' ' || c == '\t' {
			if len(current) > 0 {
				args = append(args, string(current))
				current = nil
			}
		} else {
			current = append(current, c)
		}
	}
	if len(current) > 0 {
		args = append(args, string(current))
	}
	return args
}
