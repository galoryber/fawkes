package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// resolveFileContents retrieves file contents from Mythic storage by checking
// actual arg values instead of relying on ParameterGroupName (which can be
// unreliable during CreateTasking). Checks "file" (upload ID) first, then
// "filename" (dropdown selection).
func resolveFileContents(taskData *agentstructs.PTTaskMessageAllData) (string, []byte, error) {
	// Try "file" first (New File upload — identified by file ID)
	fileID, _ := taskData.Args.GetStringArg("file")
	if fileID != "" {
		search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
			AgentFileID: fileID,
		})
		if err != nil || !search.Success || len(search.Files) == 0 {
			return "", nil, fmt.Errorf("failed to find uploaded file")
		}
		getResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
			AgentFileID: fileID,
		})
		if err != nil || !getResp.Success {
			return "", nil, fmt.Errorf("failed to get file contents")
		}
		return search.Files[0].Filename, getResp.Content, nil
	}

	// Try "filename" (Default group dropdown)
	filename, _ := taskData.Args.GetStringArg("filename")
	if filename == "" {
		return "", nil, fmt.Errorf("no file provided (file upload or filename selection required)")
	}
	search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
		CallbackID:      taskData.Callback.ID,
		Filename:        filename,
		LimitByCallback: false,
		MaxResults:      -1,
	})
	if err != nil || !search.Success || len(search.Files) == 0 {
		return "", nil, fmt.Errorf("file not found: %s", filename)
	}
	getResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
		AgentFileID: search.Files[0].AgentFileId,
	})
	if err != nil || !getResp.Success {
		return "", nil, fmt.Errorf("failed to get file contents")
	}
	return filename, getResp.Content, nil
}
