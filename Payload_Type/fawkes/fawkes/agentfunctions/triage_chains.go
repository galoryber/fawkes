package agentfunctions

import (
	"encoding/json"
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// reconPortscanDone handles portscan completion, creates smb share enum subtask for hosts with port 445 open.
func reconPortscanDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	if responseText == "" {
		completed := true
		response.Completed = &completed
		msg := "Recon Chain: portscan returned no results"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	smbHosts := parsePortScanForPort(responseText, 445)

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 1/4] Portscan complete. Found %d hosts with SMB (445) open.", len(smbHosts))),
	})

	if len(smbHosts) == 0 {
		completed := true
		response.Completed = &completed
		msg := "Recon Chain complete: no SMB hosts found"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	chainCtx := extractChainContext(taskData.Task.Stdout)

	username := chainCtx["username"]
	password := chainCtx["password"]
	hash := chainCtx["hash"]

	if username == "" {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Recon Chain: %d SMB hosts found but no credentials provided — skipping share enumeration. Run with -username/-password for full chain.", len(smbHosts))
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	hostsStr := strings.Join(smbHosts, ",")
	params := map[string]interface{}{
		"hosts":    hostsStr,
		"username": username,
		"filter":   "all",
	}
	if password != "" {
		params["password"] = password
	}
	if hash != "" {
		params["hash"] = hash
	}
	paramsJSON, _ := json.Marshal(params)

	callbackFunc := "reconShareHuntDone"
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
		msg := fmt.Sprintf("Recon Chain: failed to create share-hunt subtask: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

func reconSMBDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	return agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}
}

func reconShareHuntDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
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
		Response: []byte(fmt.Sprintf("[Step 2/4] Share hunt complete. Found ~%d interesting files on remote shares.", fileCount)),
	})

	callbackFunc := "reconTriageDone"
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
		msg := fmt.Sprintf("Recon Chain: share hunt done but failed to start local triage: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

func reconTriageDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte("[Step 3/4] Local triage complete."),
	})

	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	summary := "=== Recon Chain Complete ===\n"
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
		TaskID:   taskData.Task.ID,
		Response: []byte(summary),
	})

	return response
}

func parsePortScanForPort(responseText string, targetPort int) []string {
	hostSet := map[string]bool{}
	targetPortStr := fmt.Sprintf("%d", targetPort)

	for _, line := range strings.Split(responseText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "Scanned") ||
			strings.HasPrefix(line, "Found") || strings.HasPrefix(line, "Host") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		host := fields[0]
		port := fields[1]

		if !strings.Contains(host, ".") && !strings.Contains(host, ":") {
			continue
		}

		if port == targetPortStr {
			hostSet[host] = true
		}
	}

	var hosts []string
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	return hosts
}
