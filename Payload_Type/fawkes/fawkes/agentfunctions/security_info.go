package agentfunctions

import (
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "security-info",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "securityinfo_new.js"),
			Author:     "@GlobeTech",
		},
		Description:         "Report security posture and active controls. Linux: SELinux, AppArmor, seccomp, ASLR, YAMA, LSM, BPF. macOS: SIP, Gatekeeper, FileVault, MDM, TCC, SSH, JAMF, ARD. Windows: Defender, Credential Guard, UAC, BitLocker, CLM.",
		HelpString:          "security-info",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1082", "T1518.001"},
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			return agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
		},
	})
}
