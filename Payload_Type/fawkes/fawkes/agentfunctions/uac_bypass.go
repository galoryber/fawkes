package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "uac-bypass",
		Description:         "Bypass User Account Control (UAC) to escalate from medium to high integrity. Registry-based hijack techniques that trigger auto-elevating Windows binaries.",
		HelpString:          "uac-bypass [-technique fodhelper|computerdefaults|sdclt|eventvwr|silentcleanup|cmstp|dismhost|wusa] [-command C:\\path\\to\\payload.exe]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1548.002", "T1218.003"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "technique",
				ModalDisplayName: "Bypass Technique",
				CLIName:          "technique",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"fodhelper", "computerdefaults", "sdclt", "eventvwr", "silentcleanup", "cmstp", "dismhost", "wusa"},
				Description:      "UAC bypass technique: fodhelper (Win10+, ms-settings hijack), computerdefaults (Win10+, ms-settings hijack), sdclt (Win10, Folder handler hijack), eventvwr (Win10+, mscfile hijack), silentcleanup (Win10+, env var hijack), cmstp (Win10+, INF file abuse), dismhost (Win10+, COM CLSID hijack), wusa (Win10+, mock trusted directory)",
				DefaultValue:     "fodhelper",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "command",
				ModalDisplayName: "Command to Execute",
				CLIName:          "command",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Command/path to execute with elevated privileges. Default: spawn new elevated callback (agent's own exe).",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "uacbypass_new.js"), Author: "@galoryber"},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			technique, _ := taskData.Args.GetStringArg("technique")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:  taskData.Task.ID,
				Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage: fmt.Sprintf("OPSEC WARNING: UAC bypass via %s technique. "+
					"Exploits auto-elevation to gain High integrity from Medium integrity context. "+
					"May trigger Defender/EDR alerts for suspicious process creation or registry manipulation.", technique),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			technique, _ := taskData.Args.GetStringArg("technique")
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    fmt.Sprintf("OPSEC AUDIT: UAC bypass via %s configured. Registry/process artifacts will be created.", technique),
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			technique, _ := taskData.Args.GetStringArg("technique")
			if technique == "" {
				technique = "fodhelper"
			}
			display := fmt.Sprintf("method: %s", technique)
			response.DisplayParams = &display
			switch technique {
			case "fodhelper", "computerdefaults":
				createArtifact(taskData.Task.ID, "Registry Write", "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command (UAC bypass via "+technique+")")
				createArtifact(taskData.Task.ID, "Process Create", "Auto-elevation trigger: "+technique+".exe")
			case "sdclt":
				createArtifact(taskData.Task.ID, "Registry Write", "HKCU\\Software\\Classes\\Folder\\shell\\open\\command (UAC bypass via sdclt)")
				createArtifact(taskData.Task.ID, "Process Create", "Auto-elevation trigger: sdclt.exe")
			case "eventvwr":
				createArtifact(taskData.Task.ID, "Registry Write", "HKCU\\Software\\Classes\\mscfile\\Shell\\Open\\command (UAC bypass via eventvwr)")
				createArtifact(taskData.Task.ID, "Process Create", "Auto-elevation trigger: eventvwr.exe")
			case "silentcleanup":
				createArtifact(taskData.Task.ID, "Registry Write", "HKCU\\Environment\\windir (UAC bypass via silentcleanup)")
				createArtifact(taskData.Task.ID, "Process Create", "Scheduled task trigger: schtasks.exe /run SilentCleanup")
			case "cmstp":
				createArtifact(taskData.Task.ID, "File Write", "%TEMP%\\CMSTP_*.inf (UAC bypass via cmstp)")
				createArtifact(taskData.Task.ID, "Process Create", "Auto-elevation trigger: cmstp.exe /au")
			case "dismhost":
				createArtifact(taskData.Task.ID, "Registry Write", "HKCU\\Software\\Classes\\CLSID\\{3ad05575-8857-4850-9277-11b85bdb8e09}\\LocalServer32 (UAC bypass via dismhost COM hijack)")
				createArtifact(taskData.Task.ID, "Process Create", "Auto-elevation trigger: pkgmgr.exe (DISM COM activation)")
			case "wusa":
				createArtifact(taskData.Task.ID, "Directory Create", "C:\\Windows \\System32\\ (mock trusted directory with trailing space)")
				createArtifact(taskData.Task.ID, "File Write", "C:\\Windows \\System32\\computerdefaults.exe (copied auto-elevating binary)")
				createArtifact(taskData.Task.ID, "Registry Write", "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command (UAC bypass via wusa mock directory)")
				createArtifact(taskData.Task.ID, "Process Create", "Auto-elevation trigger: computerdefaults.exe from mock trusted directory")
			default:
				createArtifact(taskData.Task.ID, "Registry Write", "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command (UAC bypass via "+technique+")")
				createArtifact(taskData.Task.ID, "Process Create", "Auto-elevation trigger: "+technique+".exe")
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
			technique, _ := processResponse.TaskData.Args.GetStringArg("technique")
			if technique == "" {
				technique = "fodhelper"
			}
			if strings.Contains(responseText, "triggered successfully") {
				createArtifact(processResponse.TaskData.Task.ID, "Privilege Escalation",
					fmt.Sprintf("[UAC Bypass] Successful elevation via %s — high integrity process spawned", technique))
			} else if strings.Contains(responseText, "Already running at high integrity") {
				createArtifact(processResponse.TaskData.Task.ID, "Privilege Escalation",
					"[UAC Bypass] Already elevated — high integrity context confirmed")
			}
			return response
		},
	})
}
