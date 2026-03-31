package agentfunctions

import (
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "hashdump",
		Description:         "Extract local account password hashes. Windows: NTLM hashes from SAM registry (requires SYSTEM). Linux: hashes from /etc/shadow (requires root). macOS: hashes from Directory Services (requires root).",
		HelpString:          "hashdump [-format json]",
		Version:             3,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.002", "T1003.008"}, // SAM + /etc/passwd + macOS DS
		SupportedUIFeatures: []string{},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "hashdump_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:                []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
			CommandCanOnlyBeLoadedLater: true,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "format",
				CLIName:       "format",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Output format (Linux/macOS only)",
				DefaultValue:  "text",
				Choices:       []string{"text", "json"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return nil
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			msg := "OPSEC WARNING: hashdump reads SAM registry hive (Windows) or /etc/shadow (Linux). "
			switch taskData.Payload.OS {
			case "Windows":
				msg += "Requires SYSTEM privileges. Accesses HKLM\\SAM and HKLM\\SYSTEM — may trigger EDR alerts for sensitive registry access."
			case "Linux":
				msg += "Requires root. Reads /etc/shadow — may be audited by auditd/SELinux."
			default:
				msg += "Requires root. Reads local credential stores — may trigger endpoint detection."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Hashdump credential extraction configured. SAM/shadow access will occur on execution.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			for _, line := range strings.Split(responseText, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// Format: username:rid:lm_hash:nt_hash:::
				parts := strings.SplitN(line, ":", 8)
				if len(parts) < 4 {
					continue
				}
				username := parts[0]
				if username == "" {
					continue
				}
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: "hash",
					Realm:          hostname,
					Account:        username,
					Credential:     strings.TrimRight(line, "\n"),
					Comment:        "hashdump (SAM)",
				})
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			switch taskData.Payload.OS {
			case "Linux":
				display := "/etc/shadow dump"
				response.DisplayParams = &display
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "FileOpen",
					ArtifactMessage:  "Read /etc/shadow + /etc/passwd (hash extraction)",
				})
			case "macOS":
				display := "Directory Services dump"
				response.DisplayParams = &display
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "FileOpen",
					ArtifactMessage:  "Read /var/db/dslocal/nodes/Default/users/*.plist (PBKDF2 hash extraction)",
				})
			default:
				display := "SAM Dump"
				response.DisplayParams = &display
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "API Call",
					ArtifactMessage:  "RegOpenKeyExW + RegQueryValueExW on SAM\\SAM\\Domains\\Account (NTLM hash extraction)",
				})
			}
			return response
		},
	})
}
