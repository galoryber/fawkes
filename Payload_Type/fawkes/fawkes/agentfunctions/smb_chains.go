package agentfunctions

import (
	"encoding/json"
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// shareSweepSharesDone handles share enumeration completion, creates share-hunt subtask.
func shareSweepSharesDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	shareCount := 0
	if responseText != "" {
		for _, line := range strings.Split(responseText, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "Shares on") && !strings.HasPrefix(line, "-") &&
				!strings.HasPrefix(line, "Name") && !strings.HasPrefix(line, "Found") {
				shareCount++
			}
		}
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 1/3] Share enumeration complete. %d shares found.", shareCount)),
	})

	if shareCount == 0 {
		completed := true
		response.Completed = &completed
		msg := "Share Sweep: no shares found — chain complete"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	// Get chain context for credentials
	chainCtx := extractChainContext(taskData.Task.Stdout)
	host := chainCtx["host"]
	username := chainCtx["username"]
	password := chainCtx["password"]
	hash := chainCtx["hash"]

	// Step 2: Run share-hunt to crawl shares for interesting files
	params := map[string]interface{}{
		"hosts":    host,
		"username": username,
		"filter":   "all",
	}
	if password != "" {
		params["password"] = password
	}
	if hash != "" {
		params["hash"] = hash
	}
	domain := chainCtx["domain"]
	if domain != "" {
		params["domain"] = domain
	}
	paramsJSON, _ := json.Marshal(params)

	callbackFunc := "shareSweepShareHuntDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "share-hunt",
			Params:                  string(paramsJSON),
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Share Sweep: shares found but failed to start share-hunt: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

// shareSweepShareHuntDone handles share-hunt completion, creates local triage subtask.
func shareSweepShareHuntDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	fileCount := 0
	if responseText != "" {
		fileCount = strings.Count(responseText, "\n")
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 2/3] Share hunt complete. ~%d interesting files found on remote shares.", fileCount)),
	})

	// Step 3: Run local triage for credential/config files
	callbackFunc := "shareSweepTriageDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "triage",
			Params:                  `{"action":"credentials"}`,
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Share Sweep: share hunt done but failed to start triage: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

// shareSweepTriageDone handles triage completion, aggregates all chain results.
func shareSweepTriageDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte("[Step 3/3] Local triage complete."),
	})

	// Aggregate all subtask results
	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	summary := "=== Share Sweep Chain Complete ===\n"
	if err == nil && searchResult.Success {
		successCount := 0
		errorCount := 0
		for _, task := range searchResult.Tasks {
			if task.Status == "error" {
				errorCount++
			} else if task.Completed {
				successCount++
			}
			summary += fmt.Sprintf("[%s] %s %s\n", task.Status, task.CommandName, task.DisplayParams)
		}
		summary += fmt.Sprintf("\nTotal: %d subtasks (%d success, %d errors)\n", len(searchResult.Tasks), successCount, errorCount)
	} else {
		summary += "Could not retrieve subtask details.\n"
	}

	completed := true
	response.Completed = &completed
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte(summary),
	})

	return response
}

// smbExfilInfo holds parsed SMB exfiltration result data.
type smbExfilInfo struct {
	Host       string `json:"host"`
	Share      string `json:"share"`
	RemotePath string `json:"remote_path"`
	FileName   string `json:"filename"`
	TotalSize  int    `json:"total_size"`
	Success    bool   `json:"success"`
}

// parseSMBExfilResult attempts to parse an SMB exfiltration result from JSON text.
func parseSMBExfilResult(text string) *smbExfilInfo {
	var result smbExfilInfo
	if err := json.Unmarshal([]byte(text), &result); err != nil || result.Host == "" {
		return nil
	}
	return &result
}

// parseSMBShareLines extracts "Shares on" lines from SMB output.
func parseSMBShareLines(text string) []string {
	var shares []string
	if !strings.Contains(text, "Shares on") && !strings.Contains(text, "SMB") {
		return shares
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "Shares on") {
			shares = append(shares, strings.TrimSpace(line))
		}
	}
	return shares
}
