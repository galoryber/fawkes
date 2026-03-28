package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "cert-check",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "certcheck_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Inspect TLS certificates on remote hosts. Identifies certificate authorities, self-signed certs, expiry, SANs, and TLS version. Useful for service discovery and identifying internal PKI.",
		HelpString:          "cert-check -host example.com\ncert-check -host 192.168.1.1 -port 8443\ncert-check -host intranet.corp.local -port 443 -timeout 5",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1590.001"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "host",
				CLIName:       "host",
				Description:   "Target hostname or IP address",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:          "port",
				CLIName:       "port",
				Description:   "TLS port to connect to (default: 443)",
				DefaultValue:  443,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "timeout",
				CLIName:       "timeout",
				Description:   "Connection timeout in seconds (default: 10)",
				DefaultValue:  10,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			if err := args.LoadArgsFromJSONString(input); err != nil {
				return args.SetArgValue("host", input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
			host, _ := taskData.Args.GetStringArg("host")
			port, _ := taskData.Args.GetNumberArg("port")
			display := fmt.Sprintf("%s:%d", host, int(port))
			response.DisplayParams = &display
			return response
		},
	})
}
