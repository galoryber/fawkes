package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "arp",
		Description:         "Display ARP table — shows IP-to-MAC address mappings for nearby hosts",
		HelpString:          "arp",
		Version:             1,
		MitreAttackMappings: []string{"T1016.001"}, // System Network Configuration Discovery: Internet Connection Discovery
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return nil
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			// Windows: GetIpNetTable API, Linux: /proc/net/arp, macOS: arp -a
			if task.Callback.OS == "macOS" {
				createArtifact(task.Task.ID, "Process Create", "arp -a")
			} else {
				createArtifact(task.Task.ID, "API Call", "GetIpNetTable / /proc/net/arp")
			}
			return agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
		},
	})
}
