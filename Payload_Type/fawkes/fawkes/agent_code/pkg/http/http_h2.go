package http

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http2"
)

// h2AwareTransport wraps an HTTP/1.1 and HTTP/2 transport, probing the
// server's protocol support on first HTTPS request and caching the result.
// This matches real browser behavior: negotiate h2 via ALPN when the server
// supports it, fall back to h1 otherwise.
type h2AwareTransport struct {
	h1       http.RoundTripper
	h2       http.RoundTripper
	h2Avail  atomic.Bool
	h2Probed atomic.Bool
	mu       sync.Mutex
}

// newH2AwareTransport creates a protocol-aware transport that uses HTTP/2
// when the server supports it. The dialFn should perform TLS handshake
// (uTLS or standard) and return the ready connection.
func newH2AwareTransport(h1 *http.Transport, dialFn func(ctx context.Context, network, addr string) (net.Conn, error)) http.RoundTripper {
	h2t := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialFn(ctx, network, addr)
		},
	}
	return &h2AwareTransport{h1: h1, h2: h2t}
}

func (t *h2AwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return t.h1.RoundTrip(req)
	}

	if t.h2Probed.Load() {
		if t.h2Avail.Load() {
			resp, err := t.h2.RoundTrip(req)
			if err == nil {
				return resp, nil
			}
			return t.h1.RoundTrip(req)
		}
		return t.h1.RoundTrip(req)
	}

	t.mu.Lock()
	if t.h2Probed.Load() {
		t.mu.Unlock()
		if t.h2Avail.Load() {
			resp, err := t.h2.RoundTrip(req)
			if err == nil {
				return resp, nil
			}
			return t.h1.RoundTrip(req)
		}
		return t.h1.RoundTrip(req)
	}

	resp, err := t.h2.RoundTrip(req)
	if err == nil {
		t.h2Avail.Store(true)
		t.h2Probed.Store(true)
		t.mu.Unlock()
		return resp, nil
	}

	t.h2Avail.Store(false)
	t.h2Probed.Store(true)
	t.mu.Unlock()
	return t.h1.RoundTrip(req)
}
