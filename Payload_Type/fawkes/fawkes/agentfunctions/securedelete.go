package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "secure-delete",
		Description:         "Securely delete files, wipe data, or destroy boot records. delete: random overwrite + removal. wipe: aggressive destruction (T1485). wipe-mbr: overwrite MBR/GPT (T1561).",
		HelpString:          "secure-delete -path /tmp/payload.bin\nsecure-delete -path /tmp/artifacts -passes 5\nsecure-delete -action wipe -path /tmp/sensitive -confirm DESTROY\nsecure-delete -action wipe-mbr -path /dev/sda -confirm DESTROY",
		Version:             3,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1070.004", "T1485", "T1561"},
		SupportedUIFeatures: []string{"file_browser:remove"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "delete: standard secure deletion (random overwrite). wipe: aggressive destruction (T1485). wipe-mbr: overwrite MBR/GPT boot record (T1561 Disk Wipe).",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"delete", "wipe", "wipe-mbr"},
				DefaultValue:     "delete",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "File/Directory Path",
				Description:      "Path to file or directory to securely delete/wipe",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "passes",
				CLIName:          "passes",
				ModalDisplayName: "Overwrite Passes",
				Description:      "Number of random data overwrite passes (default: 3 for delete, 7 for wipe)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     3,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "confirm",
				CLIName:          "confirm",
				ModalDisplayName: "Safety Confirmation",
				Description:      "Type DESTROY to confirm wipe action (safety gate for data destruction)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			msg := fmt.Sprintf("OPSEC WARNING: Secure deletion of %s. Overwrites file contents with random data before removing. Creates write I/O patterns detectable by HIDS/FIM.", path)
			if action == "wipe" {
				msg = fmt.Sprintf("CRITICAL OPSEC WARNING: Data Destruction (T1485) — wiping %s with zeros+ones+random pattern. This is a destructive operation that cannot be reversed. Sustained I/O patterns and file deletion volume will trigger behavioral analytics. Only proceed in authorized purple team exercises.", path)
			} else if action == "wipe-mbr" {
				msg = fmt.Sprintf("CRITICAL OPSEC WARNING: Disk Wipe (T1561) — destroying MBR/GPT on %s. This renders the system UNBOOTABLE. "+
					"The boot record cannot be recovered without backup. Requires root/Administrator. "+
					"This is the most destructive operation available — use ONLY in authorized purple team exercises simulating wiper malware.", path)
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			if action == "wipe" && strings.Contains(responseText, "wiped") {
				tagTask(processResponse.TaskData.Task.ID, "IMPACT",
					"Data destruction: aggressive wipe (T1485)")
				logOperationEvent(processResponse.TaskData.Task.ID,
					"[IMPACT] Data destruction completed — aggressive wipe pattern (T1485)", true)
			} else if action == "wipe-mbr" && strings.Contains(responseText, "MBR/GPT wiped") {
				tagTask(processResponse.TaskData.Task.ID, "IMPACT",
					"Disk wipe: MBR/GPT destroyed (T1561)")
				logOperationEvent(processResponse.TaskData.Task.ID,
					"[IMPACT] Disk wipe completed — MBR/GPT boot record destroyed (T1561)", true)
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Secure deletion completed. Multi-pass overwrite generates distinctive I/O patterns. File deletion entries remain in USN journal. MFT entry persists after overwrite.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			display := fmt.Sprintf("%s %s", action, path)
			response.DisplayParams = &display
			if action == "wipe-mbr" {
				createArtifact(taskData.Task.ID, "Impact", fmt.Sprintf("Disk wipe (T1561): MBR/GPT destroy on %s", path))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[IMPACT] Disk wipe started: MBR/GPT destruction on %s", path), true)
			} else if action == "wipe" {
				createArtifact(taskData.Task.ID, "Impact", fmt.Sprintf("Data destruction (T1485): wipe %s", path))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[IMPACT] Data destruction started: wipe %s", path), true)
			} else {
				createArtifact(taskData.Task.ID, "File Delete", fmt.Sprintf("Secure deletion of %s", path))
			}
			return response
		},
	})
}
