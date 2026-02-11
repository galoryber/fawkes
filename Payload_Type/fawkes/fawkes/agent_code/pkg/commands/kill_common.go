package commands

// KillParams represents the JSON parameters for the kill command
type KillParams struct {
	PID int `json:"pid"`
}
