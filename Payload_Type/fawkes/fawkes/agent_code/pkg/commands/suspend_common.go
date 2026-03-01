package commands

// SuspendParams represents the JSON parameters for the suspend command
type SuspendParams struct {
	Action string `json:"action"`
	PID    int    `json:"pid"`
}
