//go:build linux || darwin
// +build linux darwin

package commands

import (
	"strings"
	"time"
)

// ccachePrincipal represents a principal in the ccache file
type ccachePrincipal struct {
	NameType   uint32
	Realm      string
	Components []string
}

func (p ccachePrincipal) String() string {
	name := strings.Join(p.Components, "/")
	if p.Realm != "" {
		return name + "@" + p.Realm
	}
	return name
}

// ccacheCredential represents a credential entry in the ccache file
type ccacheCredential struct {
	Client      ccachePrincipal
	Server      ccachePrincipal
	KeyType     int32 // changed from uint16 to match ccache v4 spec
	AuthTime    time.Time
	StartTime   time.Time
	EndTime     time.Time
	RenewTill   time.Time
	IsSKey      bool
	TicketFlags uint32
	TicketData  []byte
}

// findCcacheFile locates the Kerberos credential cache file
