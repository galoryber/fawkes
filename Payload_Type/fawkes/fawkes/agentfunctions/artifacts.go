package agentfunctions

import (
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

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
	var newCreds []mythicrpc.MythicRPCCredentialCreateCredentialData
	for _, c := range creds {
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
