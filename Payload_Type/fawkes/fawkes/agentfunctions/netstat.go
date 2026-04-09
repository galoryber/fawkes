package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "net-stat",
		Description:         "List active network connections and listening ports. Supports filtering by state, protocol, port, or PID.",
		HelpString:          "net-stat [-state <LISTEN|ESTABLISHED|...>] [-proto <tcp|udp>] [-port <number>] [-pid <number>]",
		Version:             3,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1049"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "state",
				CLIName:       "state",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by connection state: LISTEN, ESTABLISHED, TIME_WAIT, CLOSE_WAIT, SYN_SENT, etc.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "proto",
				CLIName:       "proto",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by protocol: tcp or udp",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "port",
				CLIName:       "port",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:  0,
				Description:   "Filter by port number (matches local or remote port)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "pid",
				CLIName:              "pid",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				Description:          "Filter by process ID",
				DynamicQueryFunction: getProcessList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "netstat_new.js"),
			Author:     "@galoryber",
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Listing active network connections and listening ports (T1049). Network enumeration is a standard discovery technique. Lower risk from API calls but process-level connection queries may be logged by EDR.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" || responseText == "[]" {
				return response
			}
			type netConn struct {
				Proto      string `json:"proto"`
				LocalIP    string `json:"local_ip"`
				LocalPort  uint32 `json:"local_port"`
				RemoteIP   string `json:"remote_ip"`
				RemotePort uint32 `json:"remote_port"`
				State      string `json:"state"`
				PID        int32  `json:"pid"`
				Process    string `json:"process"`
			}
			var conns []netConn
			if err := json.Unmarshal([]byte(responseText), &conns); err != nil {
				return response
			}
			for _, c := range conns {
				if c.State != "LISTEN" && c.State != "ESTABLISHED" {
					continue
				}
				proc := ""
				if c.Process != "" {
					proc = fmt.Sprintf(" (%s/%d)", c.Process, c.PID)
				} else if c.PID > 0 {
					proc = fmt.Sprintf(" (PID %d)", c.PID)
				}
				var msg string
				if c.State == "LISTEN" {
					msg = fmt.Sprintf("%s LISTEN %s:%d%s", c.Proto, c.LocalIP, c.LocalPort, proc)
				} else {
					msg = fmt.Sprintf("%s %s:%d → %s:%d%s", c.Proto, c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, proc)
				}
				createArtifact(processResponse.TaskData.Task.ID, "Network Connection", msg)
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			state, _ := taskData.Args.GetStringArg("state")
			proto, _ := taskData.Args.GetStringArg("proto")
			port, _ := taskData.Args.GetNumberArg("port")
			pid, _ := parsePIDFromArg(taskData)
			display := "Network connections"
			if state != "" {
				display += fmt.Sprintf(", state=%s", state)
			}
			if proto != "" {
				display += fmt.Sprintf(", proto=%s", proto)
			}
			if port != 0 {
				display += fmt.Sprintf(", port=%d", int(port))
			}
			if pid != 0 {
				display += fmt.Sprintf(", pid=%d", pid)
			}
			response.DisplayParams = &display
			return response
		},
	})
}
