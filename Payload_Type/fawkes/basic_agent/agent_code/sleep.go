package sleep

import (
	// Standard
	"encoding/json"

	structs "github.com/MythicMeta/MythicContainer/agent_structs"
	//"github.com/MythicAgents/freyja/Payload_Type/freyja/agent_code/pkg/profiles"
	// Freyja
	//"github.com/MythicAgents/freyja/Payload_Type/freyja/agent_code/pkg/utils/structs"
)

type Args struct {
	Interval int `json:"interval"`
	Jitter   int `json:"jitter"`
}

// Run - interface method that retrieves a process list
func Run(task structs.Task) {
	args := Args{}
	err := json.Unmarshal([]byte(task.Params), &args)
	if err != nil {
		errResp := task.NewResponse()
		errResp.SetError(err.Error())
		task.Job.SendResponses <- errResp
		return
	}
	output := ""
	if args.Interval >= 0 {
		output += profiles.UpdateAllSleepInterval(args.Interval)
	}
	if args.Jitter >= 0 && args.Jitter <= 100 {
		output += profiles.UpdateAllSleepJitter(args.Jitter)
	}
	msg := task.NewResponse()
	msg.UserOutput = output
	sleepString := profiles.GetSleepString()
	msg.ProcessResponse = &sleepString
	msg.Completed = true
	task.Job.SendResponses <- msg
	return
}
