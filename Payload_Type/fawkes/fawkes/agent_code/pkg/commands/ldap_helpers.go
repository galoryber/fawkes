package commands

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ldapDial connects to an LDAP server with a 10-second timeout.
// Uses LDAPS (port 636) when useTLS is true, LDAP (port 389) otherwise.
func ldapDial(server string, port int, useTLS bool) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if useTLS {
		return ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", server, port),
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return ldap.DialURL(fmt.Sprintf("ldap://%s:%d", server, port),
		ldap.DialWithDialer(dialer))
}

// ldapBindSimple binds to an LDAP connection with username/password.
// Falls back to anonymous bind if both username and password are empty.
func ldapBindSimple(conn *ldap.Conn, username, password string) error {
	if username != "" && password != "" {
		return conn.Bind(username, password)
	}
	return conn.UnauthenticatedBind("")
}
