//go:build !windows

package http

import (
	"net/http"
	"net/url"
)

// systemProxyFunc returns a proxy resolution function for non-Windows platforms.
// Uses HTTP_PROXY / HTTPS_PROXY / NO_PROXY environment variables.
func systemProxyFunc() func(*http.Request) (*url.URL, error) {
	return http.ProxyFromEnvironment
}
