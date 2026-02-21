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
