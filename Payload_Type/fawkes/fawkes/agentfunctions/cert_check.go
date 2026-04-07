package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

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
				Name:                 "host",
				CLIName:              "host",
				Description:          "Target hostname or IP address",
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
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
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			// Extract Subject and Self-Signed status from the leaf certificate
			subjectRe := regexp.MustCompile(`Subject:\s+(.+)`)
			selfSignedRe := regexp.MustCompile(`Self-Signed:\s+(\S+)`)
			validityRe := regexp.MustCompile(`Validity:\s+(\S+)`)

			subject := ""
			selfSigned := ""
			validity := ""
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if subject == "" {
					if m := subjectRe.FindStringSubmatch(trimmed); m != nil {
						subject = m[1]
					}
				}
				if selfSigned == "" {
					if m := selfSignedRe.FindStringSubmatch(trimmed); m != nil {
						selfSigned = m[1]
					}
				}
				if validity == "" {
					if m := validityRe.FindStringSubmatch(trimmed); m != nil {
						validity = m[1]
					}
				}
			}
			if subject != "" {
				msg := fmt.Sprintf("TLS cert: %s", subject)
				if selfSigned == "YES" {
					msg += " (self-signed)"
				}
				if validity != "" && validity != "OK" {
					msg += fmt.Sprintf(" [%s]", validity)
				}
				createArtifact(processResponse.TaskData.Task.ID, "Certificate", msg)
			}
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Certificate enumeration connects to remote hosts to read TLS certificates. Network monitoring may log outbound TLS connections to non-standard ports or unexpected destinations.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
