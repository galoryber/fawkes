package commands

// vssArgs holds parameters for all VSS/Impact actions across platforms.
type vssArgs struct {
	Action  string `json:"action"`
	Volume  string `json:"volume"`
	ID      string `json:"id"`
	Source  string `json:"source"`
	Dest    string `json:"dest"`
	Confirm bool   `json:"confirm"`
}
