package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "process-tree",
		Description:         "Display process hierarchy as a tree showing parent-child relationships. Helps identify injection targets, security tools, and privilege context.",
		HelpString:          "process-tree\nprocess-tree -pid 1234\nprocess-tree -filter svchost",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1057"},
		SupportedUIFeatures: []string{"process_browser:list"},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "processtree_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "pid",
				CLIName:          "pid",
				ModalDisplayName: "Root PID",
				Description:      "Show tree starting from this PID (default: all roots)",
				DynamicQueryFunction: getProcessList,
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "filter",
				CLIName:          "filter",
				ModalDisplayName: "Filter",
				Description:      "Only show processes matching this name filter",
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Process tree enumeration maps parent-child process relationships. Reveals process hierarchy which is standard reconnaissance — repeated calls may trigger EDR behavioral alerts.",
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

			type treeProc struct {
				pid   int
				name  string
				user  string
				ppid  int
				depth int
			}
			processLineRe := regexp.MustCompile(`(\d+):\s+(.+?)(?:\s+\[(.+)\])?\s*$`)

			var parsed []treeProc
			depthStack := make(map[int]int) // depth → most recent PID at that depth

			for _, line := range strings.Split(responseText, "\n") {
				if line == "" || strings.HasPrefix(line, "[*]") {
					continue
				}
				m := processLineRe.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				pid, _ := strconv.Atoi(m[1])
				name := m[2]
				user := m[3]

				stripped := strings.TrimRight(line[:strings.Index(line, m[0])], " ")
				depth := 0
				if len(stripped) > 0 {
					depth = (len(stripped) + 4) / 4
				}

				ppid := 0
				if depth > 0 {
					ppid = depthStack[depth-1]
				}
				depthStack[depth] = pid

				parsed = append(parsed, treeProc{pid: pid, name: name, user: user, ppid: ppid, depth: depth})
			}

			if len(parsed) > 0 {
				createArtifact(processResponse.TaskData.Task.ID, "Process Discovery",
					fmt.Sprintf("process-tree: %d processes enumerated", len(parsed)))

				host := processResponse.TaskData.Callback.Host
				rpcProcesses := make([]mythicrpc.MythicRPCProcessCreateProcessData, len(parsed))
				for i, p := range parsed {
					rpcProcesses[i] = mythicrpc.MythicRPCProcessCreateProcessData{
						Host:            &host,
						ProcessID:       p.pid,
						ParentProcessID: p.ppid,
						Name:            p.name,
						User:            p.user,
					}
				}
				if _, err := mythicrpc.SendMythicRPCProcessCreate(mythicrpc.MythicRPCProcessCreateMessage{
					TaskID:    processResponse.TaskData.Task.ID,
					Processes: rpcProcesses,
				}); err != nil {
					logging.LogError(err, "Failed to populate process browser from process-tree")
				}
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Process tree enumeration completed. Parent-child relationships reveal process hierarchy — useful for identifying injection targets and security products. CreateToolhelp32Snapshot/proc filesystem access may be logged by EDR. Results inform process hollowing and migration decisions.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			pid, _ := parsePIDFromArg(taskData)
			filter, _ := taskData.Args.GetStringArg("filter")
			dp := ""
			if pid > 0 {
				dp = fmt.Sprintf("pid: %d", pid)
			}
			if filter != "" {
				if dp != "" {
					dp += ", "
				}
				dp += fmt.Sprintf("filter: %s", filter)
			}
			if dp != "" {
				response.DisplayParams = &dp
			}
			return response
		},
	})
}
