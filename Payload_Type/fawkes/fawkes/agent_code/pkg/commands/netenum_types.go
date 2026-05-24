package commands


// NetEnumCommand provides cross-platform user, group, session, and share enumeration.
type NetEnumCommand struct{}

func (c *NetEnumCommand) Name() string {
	return "net-enum"
}

func (c *NetEnumCommand) Description() string {
	return "Network enumeration: users, groups, shares, sessions"
}

type netEnumArgs struct {
	Action  string `json:"action"`
	Target  string `json:"target"`
	Group   string `json:"group"`
	Timeout int    `json:"timeout"`
}

// netEnumEntry is the JSON output for most net-enum actions.
type netEnumEntry struct {
	Name      string `json:"name"`
	Comment   string `json:"comment,omitempty"`
	Type      string `json:"type,omitempty"`
	Source    string `json:"source,omitempty"`
	Flags     string `json:"flags,omitempty"`
	DNS       string `json:"dns,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Server    string `json:"server,omitempty"`
	Path      string `json:"path,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Client    string `json:"client,omitempty"`
	Time      string `json:"time,omitempty"`
	Idle      string `json:"idle,omitempty"`
	Opens     int    `json:"opens,omitempty"`
	Transport string `json:"transport,omitempty"`
	UID       int    `json:"uid,omitempty"`
	GID       int    `json:"gid,omitempty"`
	Shell     string `json:"shell,omitempty"`
	Home      string `json:"home,omitempty"`
}

