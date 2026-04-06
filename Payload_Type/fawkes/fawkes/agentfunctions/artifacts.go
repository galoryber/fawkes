package agentfunctions

import (
	"encoding/json"
	"strings"

	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// logOperationEvent creates an entry in Mythic's Operation Event Log visible in the
// UI event feed. Used for high-risk operations (credential dumping, lateral movement,
// persistence, system modification) to provide an audit trail for operators.
func logOperationEvent(taskID int, message string, warning bool) {
	_, err := mythicrpc.SendMythicRPCOperationEventLogCreate(mythicrpc.MythicRPCOperationEventLogCreateMessage{
		TaskID:       &taskID,
		Message:      message,
		Warning:      warning,
		MessageLevel: mythicrpc.MESSAGE_LEVEL_INFO,
	})
	if err != nil {
		logging.LogError(err, "Failed to create operation event log", "task_id", taskID)
	}
}

// createArtifact logs an operational artifact to Mythic's artifact tracking system.
// This provides operators with a clear record of all opsec-relevant actions taken
// during an engagement. Errors are logged but do not fail the task.
func createArtifact(taskID int, baseArtifact string, message string) {
	_, err := mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
		TaskID:           taskID,
		BaseArtifactType: baseArtifact,
		ArtifactMessage:  message,
	})
	if err != nil {
		logging.LogError(err, "Failed to create artifact", "task_id", taskID, "type", baseArtifact)
	}
}

// extractChainContext parses a JSON chain context map from a task's Stdout field.
// Mythic appends framework messages (e.g., "args aren't being used") to Stdout,
// so a plain json.Unmarshal on the full string fails. This function tries the full
// string first, then falls back to line-by-line parsing to find the JSON object.
func extractChainContext(stdout string) map[string]string {
	var ctx map[string]string
	// Fast path: if Stdout is pure JSON (no extra lines appended)
	if err := json.Unmarshal([]byte(stdout), &ctx); err == nil {
		return ctx
	}
	// Slow path: Mythic appended extra lines — try each line
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") {
			if err := json.Unmarshal([]byte(line), &ctx); err == nil {
				return ctx
			}
		}
	}
	return map[string]string{}
}

// isAllZeros returns true if the string consists entirely of '0' characters.
func isAllZeros(s string) bool {
	for _, c := range s {
		if c != '0' {
			return false
		}
	}
	return len(s) > 0
}

// registerCredentials sends extracted credentials to Mythic's credential vault,
// skipping duplicates that already exist. Used by ProcessResponse hooks to register
// credentials discovered during command execution.
func registerCredentials(taskID int, creds []mythicrpc.MythicRPCCredentialCreateCredentialData) {
	if len(creds) == 0 {
		return
	}
	// Filter out credentials that already exist in the vault
	// Also sanitize: strip null bytes that break GraphQL queries
	var newCreds []mythicrpc.MythicRPCCredentialCreateCredentialData
	for _, c := range creds {
		c.Account = strings.ReplaceAll(c.Account, "\x00", "")
		c.Credential = strings.ReplaceAll(c.Credential, "\x00", "")
		c.Realm = strings.ReplaceAll(c.Realm, "\x00", "")
		c.Comment = strings.ReplaceAll(c.Comment, "\x00", "")
		if c.Credential == "" {
			continue // skip empty credentials after sanitization
		}
		account := c.Account
		realm := c.Realm
		credType := c.CredentialType
		searchResp, err := mythicrpc.SendMythicRPCCredentialSearch(mythicrpc.MythicRPCCredentialSearchMessage{
			TaskID: taskID,
			SearchCredentials: mythicrpc.MythicRPCCredentialSearchCredentialData{
				Account: &account,
				Realm:   &realm,
				Type:    &credType,
			},
		})
		if err != nil || !searchResp.Success || len(searchResp.Credentials) == 0 {
			newCreds = append(newCreds, c)
		}
	}
	if len(newCreds) == 0 {
		return
	}
	_, err := mythicrpc.SendMythicRPCCredentialCreate(mythicrpc.MythicRPCCredentialCreateMessage{
		TaskID:      taskID,
		Credentials: newCreds,
	})
	if err != nil {
		logging.LogError(err, "Failed to register credentials in vault", "task_id", taskID, "count", len(newCreds))
	}
}
