package commands

type getPrivsParams struct {
	Action    string `json:"action"`
	Privilege string `json:"privilege"`
}

// privOutputEntry represents a privilege/capability for JSON output
type privOutputEntry struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
}

// privsOutput wraps the privilege listing with identity metadata
type privsOutput struct {
	Identity   string            `json:"identity"`
	Source     string            `json:"source"`
	Integrity  string            `json:"integrity"`
	Privileges []privOutputEntry `json:"privileges"`
}
