package main

import (
	fawkes "fawkes/basic_agent/agentfunctions"
	"os"
	"path/filepath"

	"github.com/MythicMeta/MythicContainer"
	"github.com/MythicMeta/MythicContainer/logging"

	structs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func main() {

	payloadService := structs.AllPayloadData.Get("fawkes")

	// Build the Payload container definition and add it
	// If running as standalone, locally, outside Mythic: export MYTHIC_SERVER_HOST=127.0.0.1
	payload, err := fawkes.NewPayload()
	if err != nil {
		logging.LogError(err, "quitting")
		os.Exit(2)
	}
	payloadService.AddPayloadDefinition(payload)

	// Add the Merlin payload build function definition
	payloadService.AddBuildFunction(fawkes.Build)

	// // Add the Merlin agent commands
	// for _, command := range commands.Commands() {
	// 	payloadService.AddCommand(command)
	// }

	// Get the Merlin icon and add it
	payloadService.AddIcon(filepath.Join(".", "basic_agent", "agentfunctions", "fawkes.svg"))
	// mytranslatorfunctions.Initialize()
	// my_webhooks.Initialize()
	// my_logger.Initialize()
	// my_event_processor.Initialize()
	// customAugmentFunctions.Initialize()
	// my_auth.Initialize()
	// sync over definitions and listen

	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{MythicContainer.MythicServicePayload})
}

// structs.AllPayloadData.Get("basicAgent").AddPayloadDefinition(payload)
// structs.AllPayloadData.Get("basicAgent").AddBuildFunction(build)
// structs.AllPayloadData.Get("basicAgent").AddIcon(filepath.Join(".", "basic_agent", "agentfunctions", "fawkes.svg"))
