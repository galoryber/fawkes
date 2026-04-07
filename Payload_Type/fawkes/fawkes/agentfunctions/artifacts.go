package agentfunctions

import (
	"encoding/json"
	"fmt"
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

// storeAgentData saves data to Mythic's AgentStorage table for cross-callback
// and cross-session reference. Uses UniqueID as a key-value key. If data already
// exists with the same UniqueID, it is overwritten. Errors are logged but do not
// fail the task.
func storeAgentData(uniqueID string, data []byte) {
	_, err := mythicrpc.SendMythicRPCAgentStorageCreate(mythicrpc.MythicRPCAgentstorageCreateMessage{
		UniqueID:    uniqueID,
		DataToStore: data,
	})
	if err != nil {
		logging.LogError(err, "Failed to store agent data", "unique_id", uniqueID)
	}
}

// searchAgentData retrieves data from Mythic's AgentStorage by UniqueID.
// Returns nil if not found or on error.
func searchAgentData(uniqueID string) []byte {
	resp, err := mythicrpc.SendMythicRPCAgentStorageSearch(mythicrpc.MythicRPCAgentstorageSearchMessage{
		SearchUniqueID: uniqueID,
	})
	if err != nil || !resp.Success || len(resp.AgentStorageMessages) == 0 {
		return nil
	}
	return resp.AgentStorageMessages[0].Data
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

	// Auto-tag the task based on credential types discovered
	credTypes := make(map[string]bool)
	for _, c := range newCreds {
		credTypes[c.CredentialType] = true
	}
	for ct := range credTypes {
		switch ct {
		case "plaintext":
			tagTask(taskID, "PLAINTEXT", fmt.Sprintf("Discovered %d plaintext credential(s)", countCredType(newCreds, ct)))
		case "hash":
			tagTask(taskID, "HASH", fmt.Sprintf("Discovered %d hash credential(s)", countCredType(newCreds, ct)))
		case "ticket":
			tagTask(taskID, "TICKET", fmt.Sprintf("Discovered %d Kerberos ticket(s)", countCredType(newCreds, ct)))
		case "key":
			tagTask(taskID, "KEY", fmt.Sprintf("Discovered %d cryptographic key(s)", countCredType(newCreds, ct)))
		default:
			tagTask(taskID, "CREDENTIAL", fmt.Sprintf("Discovered %d %s credential(s)", countCredType(newCreds, ct), ct))
		}
	}
}

// countCredType counts credentials of a specific type.
func countCredType(creds []mythicrpc.MythicRPCCredentialCreateCredentialData, credType string) int {
	n := 0
	for _, c := range creds {
		if c.CredentialType == credType {
			n++
		}
	}
	return n
}
