package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// credHarvestDumpAllComplete aggregates results from the parallel credential harvest subtask group.
func credHarvestDumpAllComplete(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	if err != nil || !searchResult.Success {
		completed := true
		response.Completed = &completed
		summary := "Credential Harvest Chain completed (could not aggregate results)"
		response.Stdout = &summary
		return response
	}

	var summaryParts []string
	successCount := 0
	errorCount := 0

	for _, task := range searchResult.Tasks {
		status := "unknown"
		if task.Completed {
			if task.Status == "error" {
				status = "ERROR"
				errorCount++
			} else {
				status = "SUCCESS"
				successCount++
			}
		}

		summaryParts = append(summaryParts, fmt.Sprintf("[%s] %s: %s", status, task.CommandName, task.DisplayParams))

		respSearch, respErr := mythicrpc.SendMythicRPCResponseSearch(mythicrpc.MythicRPCResponseSearchMessage{
			TaskID: task.ID,
		})
		if respErr == nil && respSearch.Success && len(respSearch.Responses) > 0 {
			for _, resp := range respSearch.Responses {
				text := string(resp.Response)
				lines := strings.Split(text, "\n")
				credCount := 0
				for _, line := range lines {
					if strings.Contains(line, ":$") || strings.Contains(line, ":::") ||
						(strings.Contains(line, "=") && (strings.Contains(strings.ToLower(line), "password") || strings.Contains(strings.ToLower(line), "secret") || strings.Contains(strings.ToLower(line), "token"))) {
						credCount++
					}
				}
				if credCount > 0 {
					summaryParts = append(summaryParts, fmt.Sprintf("  → %d potential credentials found", credCount))
				}
			}
		}
	}

	completed := true
	response.Completed = &completed
	summary := fmt.Sprintf("=== Credential Harvest Chain Complete ===\nSubtasks: %d success, %d errors\n\n%s",
		successCount, errorCount, strings.Join(summaryParts, "\n"))
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   parentID,
		Response: []byte(summary),
	})

	return response
}

// credHarvestFullSweepComplete aggregates results from the full credential sweep subtask group.
func credHarvestFullSweepComplete(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	if err != nil || !searchResult.Success {
		completed := true
		response.Completed = &completed
		summary := "Full Credential Sweep completed (could not aggregate results)"
		response.Stdout = &summary
		return response
	}

	var summaryParts []string
	successCount := 0
	errorCount := 0

	for _, task := range searchResult.Tasks {
		status := "unknown"
		if task.Completed {
			if task.Status == "error" {
				status = "ERROR"
				errorCount++
			} else {
				status = "SUCCESS"
				successCount++
			}
		}
		summaryParts = append(summaryParts, fmt.Sprintf("[%s] %s: %s", status, task.CommandName, task.DisplayParams))
	}

	completed := true
	response.Completed = &completed
	summary := fmt.Sprintf("=== Full Credential Sweep Complete ===\nSubtasks: %d success, %d errors\n\n%s",
		successCount, errorCount, strings.Join(summaryParts, "\n"))
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   parentID,
		Response: []byte(summary),
	})

	return response
}

// getSubtaskResponses fetches all response text for a given task ID.
func getSubtaskResponses(taskID int) string {
	respSearch, err := mythicrpc.SendMythicRPCResponseSearch(mythicrpc.MythicRPCResponseSearchMessage{
		TaskID: taskID,
	})
	if err != nil || !respSearch.Success || len(respSearch.Responses) == 0 {
		return ""
	}
	var parts []string
	for _, resp := range respSearch.Responses {
		parts = append(parts, string(resp.Response))
	}
	return strings.Join(parts, "\n")
}

type harvestedCredential struct {
	Account string
	Type    string
	Value   string
	Source  string
}

func parseShadowHashes(text string) []harvestedCredential {
	var creds []harvestedCredential
	if !strings.Contains(text, "/etc/shadow") && !strings.Contains(text, "Password Hashes") {
		return creds
	}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, ":$") {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 3)
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		creds = append(creds, harvestedCredential{
			Account: parts[0], Type: "hash",
			Value: parts[1], Source: "shadow",
		})
	}
	return creds
}

func parseEnvVarCredentials(text string) []harvestedCredential {
	var creds []harvestedCredential
	if !strings.Contains(text, "Sensitive Environment Variables") {
		return creds
	}
	inEnvSection := false
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "Sensitive Environment Variables") {
			inEnvSection = true
			continue
		}
		if inEnvSection && strings.HasPrefix(line, "===") {
			break
		}
		if !inEnvSection {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if idx := strings.Index(trimmed, "="); idx > 0 {
			varName := trimmed[:idx]
			varValue := trimmed[idx+1:]
			if varValue != "" {
				creds = append(creds, harvestedCredential{
					Account: varName, Type: "plaintext",
					Value: varValue, Source: "env",
				})
			}
		}
	}
	return creds
}
