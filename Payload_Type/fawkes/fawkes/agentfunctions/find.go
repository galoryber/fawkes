package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/mitchellh/mapstructure"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "find",
		Description:         "Search for files by name, size, date, permissions, or owner. Find SUID binaries, world-writable files, or files owned by specific users",
		HelpString:          "find -path <dir> -pattern <glob> [-min_size <bytes>] [-max_size <bytes>] [-newer <minutes>] [-older <minutes>] [-type f|d] [-perm suid|sgid|writable|executable|<octal>] [-owner <user|uid>]",
		Version:             4,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1083"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "find.js"),
			Author:     "@galoryber",
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "path",
				ModalDisplayName: "Search Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Directory to search in (default: current directory)",
				DefaultValue:     ".",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "pattern",
				ModalDisplayName: "File Pattern",
				CLIName:          "pattern",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Glob pattern to match filenames (e.g. *.txt, *.conf, password*). Defaults to * when filters are set.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "max_depth",
				ModalDisplayName: "Max Depth",
				CLIName:          "max_depth",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum directory depth to search (default: 10)",
				DefaultValue:     10,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "min_size",
				ModalDisplayName: "Min Size (bytes)",
				CLIName:          "min_size",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Minimum file size in bytes (0 = no minimum)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "max_size",
				ModalDisplayName: "Max Size (bytes)",
				CLIName:          "max_size",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum file size in bytes (0 = no maximum)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "newer",
				ModalDisplayName: "Newer Than (min)",
				CLIName:          "newer",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Only files modified within the last N minutes (0 = no filter)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "older",
				ModalDisplayName: "Older Than (min)",
				CLIName:          "older",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Only files modified more than N minutes ago (0 = no filter)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "type",
				ModalDisplayName: "Type Filter",
				CLIName:          "type",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Filter by type: 'f' for files only, 'd' for directories only (empty = both)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "perm",
				ModalDisplayName: "Permission Filter",
				CLIName:          "perm",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Filter by permissions: 'suid', 'sgid', 'writable' (world-writable), 'executable', or octal (e.g. '4000' for SUID, '0002' for world-writable)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "owner",
				ModalDisplayName: "Owner Filter",
				CLIName:          "owner",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Filter by file owner: username (e.g. 'root') or numeric UID (e.g. '0')",
				DefaultValue:     "",
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
			if err := args.LoadArgsFromJSONString(input); err != nil {
				// Plain text — treat as glob pattern
				args.SetManualArgs(input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			// Check if this is from the file browser (has full_path field)
			fileBrowserData := agentstructs.FileBrowserTask{}
			if err := mapstructure.Decode(input, &fileBrowserData); err == nil && fileBrowserData.FullPath != "" {
				args.AddArg(agentstructs.CommandParameter{
					Name:          "path",
					ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
					DefaultValue:  fileBrowserData.FullPath,
				})
				return nil
			}
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			path, _ := taskData.Args.GetStringArg("path")
			pattern, _ := taskData.Args.GetStringArg("pattern")
			minSize, _ := taskData.Args.GetNumberArg("min_size")
			maxSize, _ := taskData.Args.GetNumberArg("max_size")
			newer, _ := taskData.Args.GetNumberArg("newer")
			older, _ := taskData.Args.GetNumberArg("older")
			typeFilter, _ := taskData.Args.GetStringArg("type")

			display := fmt.Sprintf("%s %s", path, pattern)
			var filters []string
			if minSize > 0 {
				filters = append(filters, fmt.Sprintf("min_size=%d", int(minSize)))
			}
			if maxSize > 0 {
				filters = append(filters, fmt.Sprintf("max_size=%d", int(maxSize)))
			}
			if newer > 0 {
				filters = append(filters, fmt.Sprintf("newer=%dm", int(newer)))
			}
			if older > 0 {
				filters = append(filters, fmt.Sprintf("older=%dm", int(older)))
			}
			if typeFilter != "" {
				filters = append(filters, fmt.Sprintf("type=%s", typeFilter))
			}
			perm, _ := taskData.Args.GetStringArg("perm")
			if perm != "" {
				filters = append(filters, fmt.Sprintf("perm=%s", perm))
			}
			owner, _ := taskData.Args.GetStringArg("owner")
			if owner != "" {
				filters = append(filters, fmt.Sprintf("owner=%s", owner))
			}
			if len(filters) > 0 {
				display += " (" + strings.Join(filters, ", ") + ")"
			}
			response.DisplayParams = &display
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
			if !strings.Contains(responseText, "Found") || !strings.Contains(responseText, "match") {
				return response
			}

			host := processResponse.TaskData.Callback.Host

			// Each result line format: "%-12s %-16s %s" = "<size>  <date>  <path>"
			lines := strings.Split(responseText, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "Found ") || strings.HasPrefix(line, "(results") || strings.Contains(line, "inaccessible") {
					continue
				}

				parts := strings.Fields(line)
				if len(parts) < 3 {
					continue
				}

				// Path is the last field (absolute path with no spaces in the format)
				filePath := parts[len(parts)-1]
				isDir := parts[0] == "<DIR>"

				// Parse modification time from YYYY-MM-DD HH:MM pattern
				var modTime uint64
				for i := 0; i < len(parts)-1; i++ {
					if len(parts[i]) == 10 && parts[i][4] == '-' && parts[i][7] == '-' {
						if t, err := time.Parse("2006-01-02 15:04", parts[i]+" "+parts[i+1]); err == nil {
							modTime = uint64(t.Unix())
						}
						break
					}
				}

				parentDir := filepath.Dir(filePath)
				baseName := filepath.Base(filePath)

				if _, err := mythicrpc.SendMythicRPCFileBrowserCreate(mythicrpc.MythicRPCFileBrowserCreateMessage{
					TaskID: processResponse.TaskData.Task.ID,
					FileBrowser: mythicrpc.MythicRPCFileBrowserCreateFileBrowserData{
						Host:       host,
						IsFile:     !isDir,
						Name:       baseName,
						ParentPath: parentDir,
						Success:    true,
						ModifyTime: modTime,
					},
				}); err != nil {
					logging.LogError(err, "Failed to create file browser entry", "path", filePath)
				}
			}
			return response
		},
	})
}
