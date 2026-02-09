package profiles

import (
	"fawkes/pkg/http"
	"fawkes/pkg/structs"
)

// Profile interface defines the C2 profile methods
type Profile interface {
	Checkin(agent *structs.Agent) error
	GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error)
	PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error)
}

// NewProfile creates a new profile based on the HTTP profile
func NewProfile(httpProfile *http.HTTPProfile) Profile {
	return httpProfile
}
