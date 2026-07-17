package agentfunctions

import (
	"encoding/json"
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
		Name:                "ls",
		Description:         "ls [path]",
		Version:             1,
		MitreAttackMappings: []string{"T1083"},
		SupportedUIFeatures: []string{"file_browser:list"},
		Author:              "@xorrior",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:        []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
			CommandIsSuggested: true,
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ls_new.js"),
			Author:     "@its_a_feature_",
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Directory listing (T1083). File/directory enumeration is a standard discovery action logged by EDR and audit policies. Access timestamps may be updated on target directories.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Directory listing completed. Results populated Mythic file browser. Repeated listings of sensitive directories (e.g., Documents, Desktop) may trigger behavioral detection.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			if path, err := taskData.Args.GetStringArg("path"); err != nil {
				logging.LogError(err, "Failed to get string arg for path")
				response.Error = err.Error()
				response.Success = false
				return response
			} else {
				response.DisplayParams = &path
			}
			return response
		},
		TaskFunctionProcessResponse: lsProcessResponse,
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			// Check if this is from the file browser (has full_path field)
			fileBrowserData := agentstructs.FileBrowserTask{}
			if err := mapstructure.Decode(input, &fileBrowserData); err == nil && fileBrowserData.FullPath != "" {
				args.AddArg(agentstructs.CommandParameter{
					Name:          "file_browser",
					ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
					DefaultValue:  true,
				})
				args.AddArg(agentstructs.CommandParameter{
					Name:          "path",
					ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
					DefaultValue:  fileBrowserData.FullPath,
				})
				return nil
			}
			// Otherwise parse as simple path dictionary (e.g., {"path": "C:\\Users"})
			if path, ok := input["path"].(string); ok {
				args.AddArg(agentstructs.CommandParameter{
					Name:          "path",
					ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
					DefaultValue:  path,
				})
			} else {
				logging.LogError(nil, "Failed to get path from dictionary input")
			}
			args.AddArg(agentstructs.CommandParameter{
				Name:          "file_browser",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:  false,
			})
			return nil
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			input = strings.TrimSpace(input)
			// Try JSON first (e.g., {"path": "C:\\Users"} or {"full_path": "..."} from API)
			var jsonArgs map[string]interface{}
			if err := json.Unmarshal([]byte(input), &jsonArgs); err == nil {
				// Check for file browser format (full_path)
				if fullPath, ok := jsonArgs["full_path"].(string); ok && fullPath != "" {
					args.AddArg(agentstructs.CommandParameter{
						Name:          "path",
						ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
						DefaultValue:  fullPath,
					})
					args.AddArg(agentstructs.CommandParameter{
						Name:          "file_browser",
						ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
						DefaultValue:  true,
					})
					return nil
				}
				// Check for explicit file_browser flag
				fileBrowser, _ := jsonArgs["file_browser"].(bool)
				if path, ok := jsonArgs["path"].(string); ok {
					args.AddArg(agentstructs.CommandParameter{
						Name:          "path",
						ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
						DefaultValue:  path,
					})
					args.AddArg(agentstructs.CommandParameter{
						Name:          "file_browser",
						ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
						DefaultValue:  fileBrowser,
					})
					return nil
				}
			}
			// Strip surrounding quotes
			if len(input) >= 2 {
				if (input[0] == '"' && input[len(input)-1] == '"') ||
					(input[0] == '\'' && input[len(input)-1] == '\'') {
					input = input[1 : len(input)-1]
				}
			}
			if input == "" {
				input = "."
			}
			args.AddArg(agentstructs.CommandParameter{
				Name:          "path",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  input,
			})
			args.AddArg(agentstructs.CommandParameter{
				Name:          "file_browser",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:  false,
			})
			return nil
		},
	})
}

type lsFileListing struct {
	Host       string        `json:"host"`
	IsFile     bool          `json:"is_file"`
	Name       string        `json:"name"`
	ParentPath string        `json:"parent_path"`
	Success    bool          `json:"success"`
	Files      []lsFileEntry `json:"files,omitempty"`
}

type lsFileEntry struct {
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	IsFile      bool   `json:"is_file"`
	Permissions string `json:"permissions"`
	Size        int64  `json:"size"`
	Owner       string `json:"owner"`
	Group       string `json:"group"`
	ModifyTime  string `json:"modify_time"`
	AccessTime  string `json:"access_time"`
}

func lsProcessResponse(msg agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
	response := agentstructs.PTTaskProcessResponseMessageResponse{
		TaskID:  msg.TaskData.Task.ID,
		Success: true,
	}
	responseText, ok := msg.Response.(string)
	if !ok || responseText == "" {
		return response
	}

	var listing lsFileListing
	if err := json.Unmarshal([]byte(responseText), &listing); err != nil {
		return response
	}
	if !listing.Success {
		return response
	}

	host := listing.Host
	if host == "" {
		host = msg.TaskData.Callback.Host
	}

	dirPath := filepath.Join(listing.ParentPath, listing.Name)

	createArtifact(msg.TaskData.Task.ID, "File Open",
		fmt.Sprintf("Directory listing: %s (%d entries, T1083)", dirPath, len(listing.Files)))

	if _, err := mythicrpc.SendMythicRPCFileBrowserCreate(mythicrpc.MythicRPCFileBrowserCreateMessage{
		TaskID: msg.TaskData.Task.ID,
		FileBrowser: mythicrpc.MythicRPCFileBrowserCreateFileBrowserData{
			Host:       host,
			IsFile:     listing.IsFile,
			Name:       listing.Name,
			ParentPath: listing.ParentPath,
			Success:    true,
		},
	}); err != nil {
		logging.LogError(err, "ls: failed to create directory browser entry",
			"host", host, "path", dirPath)
	}

	for _, f := range listing.Files {
		perms := make(map[string]interface{})
		if f.Permissions != "" {
			perms["permissions"] = f.Permissions
		}
		if f.Owner != "" {
			perms["owner"] = f.Owner
		}
		if f.Group != "" {
			perms["group"] = f.Group
		}

		entry := mythicrpc.MythicRPCFileBrowserCreateFileBrowserData{
			Host:        host,
			IsFile:      f.IsFile,
			Name:        f.Name,
			ParentPath:  dirPath,
			Success:     true,
			Permissions: perms,
			Size:        uint64(f.Size),
		}
		if t, err := parseTimestamp(f.ModifyTime); err == nil {
			entry.ModifyTime = t
		}
		if t, err := parseTimestamp(f.AccessTime); err == nil {
			entry.AccessTime = t
		}

		if _, err := mythicrpc.SendMythicRPCFileBrowserCreate(mythicrpc.MythicRPCFileBrowserCreateMessage{
			TaskID:      msg.TaskData.Task.ID,
			FileBrowser: entry,
		}); err != nil {
			logging.LogError(err, "ls: failed to create file browser entry",
				"host", host, "file", f.Name)
		}
	}
	return response
}

func parseTimestamp(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
	}
	if err != nil {
		return 0, err
	}
	return uint64(t.Unix()), nil
}
