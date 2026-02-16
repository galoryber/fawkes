package main

import (
	fawkesAgent "fawkes/fawkes/agentfunctions"

	"github.com/MythicMeta/MythicContainer"
)

func main() {
	// Load agent function definitions (init() functions in agentfunctions/)
	fawkesAgent.Initialize()

	// Sync definitions with Mythic and listen for build/task requests
	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{
		MythicContainer.MythicServiceC2,
		MythicContainer.MythicServicePayload,
	})
}
