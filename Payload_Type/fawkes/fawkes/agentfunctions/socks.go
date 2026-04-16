package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/MythicMeta/MythicContainer/rabbitmq"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "socks",
		Description:         "Start, stop, or view stats for the SOCKS5 proxy through this callback. Supports TCP and UDP relay with optional bandwidth limiting.",
		HelpString:          "socks start [port]  /  socks stop [port]  /  socks stats  /  socks bandwidth [kb/s]",
		Version:             3,
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
				Description:   "Start or stop the SOCKS proxy, view stats, or set bandwidth limit",
				Choices:       []string{"start", "stop", "stats", "bandwidth"},
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
			{
				Name:          "bandwidth_kbs",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Per-connection bandwidth limit in KB/s (0 = unlimited). Applied on start or via 'bandwidth' action.",
				DefaultValue:  0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "socks_new.js"), Author: "@galoryber"},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: SOCKS proxy operation completed. Proxy connections generate network traffic patterns (many outbound connections from a single process). NDR and host-based firewalls may log unusual connection volumes.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// Support: socks start 1080  /  socks stop 1080  /  socks stats  /  socks bandwidth 500
			if input == "" {
				return nil
			}
			parts := splitArgs(input)
			if len(parts) >= 1 {
				args.SetArgValue("action", parts[0])
			}
			if len(parts) >= 2 {
				if val, err := strconv.Atoi(parts[1]); err == nil {
					action, _ := args.GetStringArg("action")
					if action == "bandwidth" {
						args.SetArgValue("bandwidth_kbs", val)
					} else {
						args.SetArgValue("port", val)
					}
				}
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Starting SOCKS5 proxy (T1090.001). Routes arbitrary traffic through the agent. Creates detectable network patterns and may expose internal services. Long-running connections increase detection risk.",
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

			// Build display params
			bwKbs, _ := taskData.Args.GetNumberArg("bandwidth_kbs")
			bwInt := int(bwKbs)
			switch action {
			case "bandwidth":
				dp := fmt.Sprintf("bandwidth %d KB/s", bwInt)
				response.DisplayParams = &dp
			default:
				dp := fmt.Sprintf("%s %d", action, portInt)
				if action == "start" && bwInt > 0 {
					dp += fmt.Sprintf(" (bandwidth: %d KB/s)", bwInt)
				}
				response.DisplayParams = &dp
			}

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

			case "stats", "bandwidth":
				// No server-side action needed — agent handles these
				break

			default:
				response.Error = fmt.Sprintf("Unknown action: %s", action)
				response.Success = false
			}

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
			if strings.Contains(responseText, "started") || strings.Contains(responseText, "Started") || strings.Contains(responseText, "listening") {
				createArtifact(processResponse.TaskData.Task.ID, "Network Connection", fmt.Sprintf("[socks] %s", responseText))
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
