package http

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type mockRoundTripper struct {
	fn func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.fn(req)
}

func okResponse() *http.Response {
	return &http.Response{StatusCode: 200, Body: http.NoBody}
}

func TestH2Aware_HTTPAlwaysUsesH1(t *testing.T) {
	var h1Called, h2Called atomic.Int32
	h1 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		h1Called.Add(1)
		return okResponse(), nil
	}}
	h2 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		h2Called.Add(1)
		return okResponse(), nil
	}}
	tr := &h2AwareTransport{h1: h1, h2: h2}

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		resp.Body.Close()
	}

	if h1Called.Load() != 5 {
		t.Errorf("h1 called %d times, want 5", h1Called.Load())
	}
	if h2Called.Load() != 0 {
		t.Errorf("h2 called %d times, want 0", h2Called.Load())
	}
}

func TestH2Aware_HTTPSProbesH2OnFirstRequest(t *testing.T) {
	var h1Called, h2Called atomic.Int32
	h1 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		h1Called.Add(1)
		return okResponse(), nil
	}}
	h2 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		h2Called.Add(1)
		return okResponse(), nil
	}}
	tr := &h2AwareTransport{h1: h1, h2: h2}

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "https://example.com/test", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		resp.Body.Close()
	}

	if h2Called.Load() != 5 {
		t.Errorf("h2 called %d times, want 5 (all via h2)", h2Called.Load())
	}
	if h1Called.Load() != 0 {
		t.Errorf("h1 called %d times, want 0", h1Called.Load())
	}
}

func TestH2Aware_FallbackToH1WhenH2Unavailable(t *testing.T) {
	var h1Called, h2Called atomic.Int32
	h1 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		h1Called.Add(1)
		return okResponse(), nil
	}}
	h2 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		h2Called.Add(1)
		return nil, fmt.Errorf("http2: unexpected ALPN protocol \"http/1.1\"; want \"h2\"")
	}}
	tr := &h2AwareTransport{h1: h1, h2: h2}

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "https://example.com/test", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		resp.Body.Close()
	}

	if h2Called.Load() != 1 {
		t.Errorf("h2 probed %d times, want 1 (probe only)", h2Called.Load())
	}
	if h1Called.Load() != 5 {
		t.Errorf("h1 called %d times, want 5", h1Called.Load())
	}
}

func TestH2Aware_H2FailureFallsBackToH1(t *testing.T) {
	var h1Called atomic.Int32
	callCount := atomic.Int32{}
	h1 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		h1Called.Add(1)
		return okResponse(), nil
	}}
	h2 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		n := callCount.Add(1)
		if n <= 2 {
			return okResponse(), nil
		}
		return nil, fmt.Errorf("connection reset")
	}}
	tr := &h2AwareTransport{h1: h1, h2: h2}

	for i := 0; i < 4; i++ {
		req, _ := http.NewRequest("GET", "https://example.com/test", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		resp.Body.Close()
	}

	if h1Called.Load() != 2 {
		t.Errorf("h1 fallback called %d times, want 2 (requests 3+4)", h1Called.Load())
	}
}

func TestH2Aware_ConcurrentProbe(t *testing.T) {
	var h2ProbeCount atomic.Int32
	h1 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		return okResponse(), nil
	}}
	h2 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		h2ProbeCount.Add(1)
		return okResponse(), nil
	}}
	tr := &h2AwareTransport{h1: h1, h2: h2}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "https://example.com/test", nil)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Errorf("RoundTrip: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()

	if !tr.h2Probed.Load() {
		t.Error("h2Probed should be true after concurrent requests")
	}
	if !tr.h2Avail.Load() {
		t.Error("h2Avail should be true (h2 mock succeeds)")
	}
}

func TestH2Aware_MixedSchemes(t *testing.T) {
	var h1Called, h2Called atomic.Int32
	h1 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		h1Called.Add(1)
		return okResponse(), nil
	}}
	h2 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		h2Called.Add(1)
		return okResponse(), nil
	}}
	tr := &h2AwareTransport{h1: h1, h2: h2}

	urls := []string{
		"http://example.com/a",
		"https://example.com/b",
		"http://example.com/c",
		"https://example.com/d",
	}

	for _, u := range urls {
		req, _ := http.NewRequest("GET", u, nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %s: %v", u, err)
		}
		resp.Body.Close()
	}

	if h1Called.Load() != 2 {
		t.Errorf("h1 called %d times, want 2 (HTTP requests)", h1Called.Load())
	}
	if h2Called.Load() != 2 {
		t.Errorf("h2 called %d times, want 2 (HTTPS requests)", h2Called.Load())
	}
}

func TestNewHTTPProfile_H2EnabledWithFingerprint(t *testing.T) {
	profile := NewHTTPProfile(ProfileConfig{
		BaseURL:        "https://example.com",
		EncryptionKey:  "dGVzdA==",
		TLSFingerprint: "chrome",
	})

	rt := profile.client.Transport
	if _, ok := rt.(*h2AwareTransport); !ok {
		t.Errorf("transport type = %T, want *h2AwareTransport (uTLS h2 wrapper)", rt)
	}
}

func TestNewHTTPProfile_H2EnabledWithRotate(t *testing.T) {
	profile := NewHTTPProfile(ProfileConfig{
		BaseURL:        "https://example.com",
		EncryptionKey:  "dGVzdA==",
		TLSFingerprint: "rotate",
	})

	rt := profile.client.Transport
	if _, ok := rt.(*h2AwareTransport); !ok {
		t.Errorf("transport type = %T, want *h2AwareTransport (rotate h2 wrapper)", rt)
	}
}

func TestNewHTTPProfile_NoH2WrapperForHTTP(t *testing.T) {
	profile := NewHTTPProfile(ProfileConfig{
		BaseURL:       "http://example.com",
		EncryptionKey: "dGVzdA==",
	})

	rt := profile.client.Transport
	if _, ok := rt.(*http.Transport); !ok {
		t.Errorf("transport type = %T, want *http.Transport (plain HTTP, no h2 wrapper)", rt)
	}
}

func TestNewHTTPProfile_ForceH2ForStdTLS(t *testing.T) {
	profile := NewHTTPProfile(ProfileConfig{
		BaseURL:       "https://example.com",
		EncryptionKey: "dGVzdA==",
	})

	rt := profile.client.Transport
	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport (std TLS)", rt)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be true for std TLS HTTPS")
	}
}

func TestH2Aware_BothFailReturnsH1Error(t *testing.T) {
	h1 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("h1: connection refused")
	}}
	h2 := &mockRoundTripper{fn: func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("h2: connection refused")
	}}
	tr := &h2AwareTransport{h1: h1, h2: h2}

	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	_, err := tr.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error when both transports fail")
	}
	if !strings.Contains(err.Error(), "h1: connection refused") {
		t.Errorf("error = %v, want h1 error (fallback)", err)
	}
}
