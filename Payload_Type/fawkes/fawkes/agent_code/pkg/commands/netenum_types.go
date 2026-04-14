package commands

import (
	"fmt"
	"time"

	"fawkes/pkg/structs"
)

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

// domainInfoOutput is the JSON output for the domaininfo action.
type domainInfoOutput struct {
	DCName      string         `json:"dc_name,omitempty"`
	DCAddress   string         `json:"dc_address,omitempty"`
	Domain      string         `json:"domain,omitempty"`
	Forest      string         `json:"forest,omitempty"`
	DCSite      string         `json:"dc_site,omitempty"`
	ClientSite  string         `json:"client_site,omitempty"`
	MinPassLen  uint32         `json:"min_password_length,omitempty"`
	MaxPassAge  uint32         `json:"max_password_age_days,omitempty"`
	MinPassAge  uint32         `json:"min_password_age_days,omitempty"`
	PassHistLen uint32         `json:"password_history_length,omitempty"`
	ForceLogoff string         `json:"force_logoff,omitempty"`
	Trusts      []netEnumEntry `json:"trusts,omitempty"`
}

// neFormatDuration converts seconds to a human-readable duration string.
func neFormatDuration(seconds uint32) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm%ds", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%dh%dm", seconds/3600, (seconds%3600)/60)
}

// netEnumWithTimeout wraps an enumeration call with a timeout.
func netEnumWithTimeout(fn func() structs.CommandResult, timeout time.Duration) structs.CommandResult {
	ch := make(chan structs.CommandResult, 1)
	go func() { ch <- fn() }()
	select {
	case result := <-ch:
		return result
	case <-time.After(timeout):
		return errorf("Error: operation timed out after %s (host may be unreachable)", timeout)
	}
}
