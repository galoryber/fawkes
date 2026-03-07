package commands

type firewallArgs struct {
	Action     string `json:"action"`
	Name       string `json:"name"`
	Direction  string `json:"direction"`
	RuleAction string `json:"rule_action"`
	Protocol   string `json:"protocol"`
	Port       string `json:"port"`
	Program    string `json:"program"`
	Filter     string `json:"filter"`
	Enabled    string `json:"enabled"`
}
