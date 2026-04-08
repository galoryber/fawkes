package agentfunctions

import (
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "vm-detect",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "vmdetect_new.js"),
			Author:     "@GlobeTech",
		},
		Description:         "Detect virtual machine and hypervisor environment. Checks MAC addresses, DMI info, VM tools, CPUID flags, and known VM file paths.",
		HelpString:          "vm-detect",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1497.001"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{},
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
				OpsecPreMessage:    "OPSEC WARNING: Detects virtual machine/hypervisor environment (T1497.001). Anti-VM checks (CPUID, registry, WMI, MAC OUI) are a well-known malware indicator that sandboxes specifically detect.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			return agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
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
			if strings.Contains(responseText, "true") || strings.Contains(responseText, "Virtual") ||
				strings.Contains(responseText, "VMware") || strings.Contains(responseText, "Hyper-V") {
				tagTask(processResponse.TaskData.Task.ID, "OPSEC",
					"Virtual machine/hypervisor environment detected (T1497.001)")
			}
			logOperationEvent(processResponse.TaskData.Task.ID,
				"[RECON] VM/hypervisor environment check (T1497.001)", false)
			return response
		},
	})
}
