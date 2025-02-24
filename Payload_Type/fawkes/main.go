package main

import (
	"github.com/MythicMeta/MythicContainer"
)

func main() {
	// load up the agent functions directory so all the init() functions execute
	//httpfunctions.Initialize()
	fawkesAgent.build()
	//mytranslatorfunctions.Initialize()
	//my_webhooks.Initialize()
	//my_logger.Initialize()
	// sync over definitions and listen
	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{
		//MythicContainer.MythicServiceC2,
		//MythicContainer.MythicServiceTranslationContainer,
		//MythicContainer.MythicServiceWebhook,
		//MythicContainer.MythicServiceLogger,
		MythicContainer.MythicServicePayload,
	})
}

// func main() {

// 	payloadService := agentstructs.AllPayloadData.Get("fawkesAgent")

// 	// Build the Payload container definition and add it
// 	// If running as standalone, locally, outside Mythic: export MYTHIC_SERVER_HOST=127.0.0.1
// 	payload, err := fawkesAgent.NewPayload()
// 	if err != nil {
// 		logging.LogError(err, "quitting")
// 		os.Exit(2)
// 	}
// 	payloadService.AddPayloadDefinition(payload)

// 	// Add the Merlin payload build function definition
// 	payloadService.AddBuildFunction(fawkesAgent.Build)

// 	// // Add the Merlin agent commands
// 	// for _, command := range commands.Commands() {
// 	// 	payloadService.AddCommand(command)
// 	// }

// 	// Get the Merlin icon and add it
// 	payloadService.AddIcon(filepath.Join(".", "basic_agent", "agentfunctions", "fawkes.svg"))
// 	// mytranslatorfunctions.Initialize()
// 	// my_webhooks.Initialize()
// 	// my_logger.Initialize()
// 	// my_event_processor.Initialize()
// 	// customAugmentFunctions.Initialize()
// 	// my_auth.Initialize()
// 	// sync over definitions and listen

// 	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{MythicContainer.MythicServicePayload})
// }

// structs.AllPayloadData.Get("basicAgent").AddPayloadDefinition(payload)
// structs.AllPayloadData.Get("basicAgent").AddBuildFunction(build)
//agentstructs.AllPayloadData.Get("basicAgent").AddIcon(filepath.Join(".", "basic_agent", "agentfunctions", "fawkes.svg"))
