package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "reg",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "reg_new.js"),
			Author:     "@galoryber",
		},
		Description: "Unified Windows Registry operations — read, write, delete, search, and save hives. Single command replaces reg-read, reg-write, reg-delete, reg-search, and reg-save.",
		HelpString:          "reg -action read -hive HKLM -path \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\" -name ProgramFilesDir\nreg -action write -hive HKCU -path \"Software\\Test\" -name Val -data hello -type REG_SZ\nreg -action delete -hive HKCU -path \"Software\\Test\" -name Val\nreg -action search -pattern password -hive HKLM -path SOFTWARE\nreg -action save -hive HKLM -path SAM -output C:\\Temp\\sam.hiv",
		Version:             1,
		MitreAttackMappings: []string{"T1012", "T1112", "T1003.002"},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Registry operation to perform",
				DefaultValue:     "read",
				Choices:          []string{"read", "write", "delete", "search", "save", "creds"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 0},
				},
			},
			{
				Name:             "hive",
				ModalDisplayName: "Registry Hive",
				CLIName:          "hive",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Registry hive",
				DefaultValue:     "HKLM",
				Choices:          []string{"HKLM", "HKCU", "HKCR", "HKU", "HKCC"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 1},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "Registry Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Registry key path",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 2},
				},
			},
			{
				Name:             "name",
				ModalDisplayName: "Value Name",
				CLIName:          "name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Value name (for read/write/delete)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 3},
				},
			},
			{
				Name:             "data",
				ModalDisplayName: "Value Data",
				CLIName:          "data",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Data to write (for write action). DWORD/QWORD: decimal or 0x hex. BINARY: hex string.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 4},
				},
			},
			{
				Name:             "reg_type",
				ModalDisplayName: "Value Type",
				CLIName:          "type",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Registry value type (for write action)",
				DefaultValue:     "REG_SZ",
				Choices:          []string{"REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 5},
				},
			},
			{
				Name:             "recursive",
				ModalDisplayName: "Recursive",
				CLIName:          "recursive",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"false", "true"},
				Description:      "Recursively delete all subkeys (for delete action)",
				DefaultValue:     "false",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 6},
				},
			},
			{
				Name:             "pattern",
				ModalDisplayName: "Search Pattern",
				CLIName:          "pattern",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Search pattern (for search action, case-insensitive)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 7},
				},
			},
			{
				Name:             "max_depth",
				ModalDisplayName: "Max Search Depth",
				CLIName:          "max_depth",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum recursion depth for search (default: 5)",
				DefaultValue:     5,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 8},
				},
			},
			{
				Name:             "max_results",
				ModalDisplayName: "Max Search Results",
				CLIName:          "max_results",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum number of search results (default: 50)",
				DefaultValue:     50,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 9},
				},
			},
			{
				Name:             "output",
				ModalDisplayName: "Output File",
				CLIName:          "output",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Output file path (for save action)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 10},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			if err := args.LoadArgsFromJSONString(input); err == nil {
				return nil
			}
			// Plain text: parse -flag value pairs
			parts := strings.Fields(input)
			for i := 0; i < len(parts); i++ {
				switch parts[i] {
				case "-action":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("action", parts[i])
					}
				case "-hive":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("hive", parts[i])
					}
				case "-path":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("path", parts[i])
					}
				case "-name":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("name", parts[i])
					}
				case "-data":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("data", parts[i])
					}
				case "-type", "-reg_type":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("reg_type", parts[i])
					}
				case "-recursive":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("recursive", parts[i])
					}
				case "-pattern":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("pattern", parts[i])
					}
				case "-max_depth":
					if i+1 < len(parts) {
						i++
						if v, err := strconv.Atoi(parts[i]); err == nil {
							args.SetArgValue("max_depth", v)
						}
					}
				case "-max_results":
					if i+1 < len(parts) {
						i++
						if v, err := strconv.Atoi(parts[i]); err == nil {
							args.SetArgValue("max_results", v)
						}
					}
				case "-output":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("output", parts[i])
					}
				}
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			hive, _ := taskData.Args.GetStringArg("hive")
			path, _ := taskData.Args.GetStringArg("path")
			var msg string
			switch action {
			case "write":
				msg = fmt.Sprintf("OPSEC WARNING: Registry write to %s\\%s (T1112). Registry modifications are logged by Sysmon Event ID 13/14 and EDR telemetry. Security products monitor Run keys, IFEO, and COM hijack paths.", hive, path)
			case "delete":
				msg = fmt.Sprintf("OPSEC WARNING: Registry key/value deletion at %s\\%s (T1112). Deletion events are logged by Sysmon Event ID 12 and may trigger EDR alerts for registry tampering.", hive, path)
			case "save":
				msg = fmt.Sprintf("OPSEC WARNING: Registry hive save from %s\\%s (T1003.002). Saving SAM/SECURITY/SYSTEM hives is a well-known credential dumping technique detected by most EDR products.", hive, path)
			case "creds":
				msg = "OPSEC WARNING: Registry credential extraction — SAM+SECURITY+SYSTEM (T1003.002). This is a high-detection technique monitored by all major EDR/AV products."
			default:
				msg = fmt.Sprintf("OPSEC WARNING: Registry read/search on %s\\%s (T1012). Registry enumeration is low-risk but may be correlated with other suspicious activity.", hive, path)
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
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
				OpsecPostMessage:    "OPSEC AUDIT: Registry operation completed. Changes are logged in the Security event log (Event ID 4657) if auditing is enabled. Registry transaction logs (.TM.blf, .regtrans-ms) may contain evidence. Use 'eventlog -action clear' to clean if needed.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			hive, _ := taskData.Args.GetStringArg("hive")
			path, _ := taskData.Args.GetStringArg("path")
			name, _ := taskData.Args.GetStringArg("name")

			var display string
			switch action {
			case "read":
				if name != "" {
					display = fmt.Sprintf("read %s\\%s -> %s", hive, path, name)
				} else {
					display = fmt.Sprintf("read %s\\%s (enumerate)", hive, path)
				}
			case "write":
				data, _ := taskData.Args.GetStringArg("data")
				regType, _ := taskData.Args.GetStringArg("reg_type")
				displayName := name
				if displayName == "" {
					displayName = "(Default)"
				}
				display = fmt.Sprintf("write %s\\%s\\%s = %s [%s]", hive, path, displayName, data, regType)
				createArtifact(taskData.Task.ID, "Registry Write", display)
			case "delete":
				if name != "" {
					display = fmt.Sprintf("delete value %s\\%s\\%s", hive, path, name)
				} else {
					recursive, _ := taskData.Args.GetStringArg("recursive")
					display = fmt.Sprintf("delete key %s\\%s (recursive=%s)", hive, path, recursive)
				}
				createArtifact(taskData.Task.ID, "Registry Write", display)
			case "search":
				pattern, _ := taskData.Args.GetStringArg("pattern")
				display = fmt.Sprintf("search %s\\%s for %q", hive, path, pattern)
			case "save":
				output, _ := taskData.Args.GetStringArg("output")
				display = fmt.Sprintf("save %s\\%s → %s", hive, path, output)
				createArtifact(taskData.Task.ID, "File Write", display)
			case "creds":
				display = "creds (SAM+SECURITY+SYSTEM)"
				createArtifact(taskData.Task.ID, "File Write", display)
			default:
				display = fmt.Sprintf("%s %s\\%s", action, hive, path)
			}
			response.DisplayParams = &display

			if action == "write" || action == "delete" {
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[SYSTEM MOD] reg %s: %s\\%s on %s", action, hive, path, taskData.Callback.Host), true)
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")

			switch action {
			case "search":
				// Track registry search as Configuration artifact
				pattern, _ := processResponse.TaskData.Args.GetStringArg("pattern")
				hive, _ := processResponse.TaskData.Args.GetStringArg("hive")
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "Configuration",
					ArtifactMessage:  fmt.Sprintf("Registry search: %s\\* for %q", hive, pattern),
				})
			case "creds":
				// Track SAM/SECURITY/SYSTEM extraction as Credential artifact
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "Credential",
					ArtifactMessage:  "Registry credential extraction: SAM + SECURITY + SYSTEM hives",
				})
			case "save":
				// Track hive save as File Write artifact
				output, _ := processResponse.TaskData.Args.GetStringArg("output")
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "File Write",
					ArtifactMessage:  fmt.Sprintf("Registry hive saved to: %s", output),
				})
			}
			return response
		},
	})
}
