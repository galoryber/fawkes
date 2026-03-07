package http

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

// --- extractChromeVersion Tests ---

func TestExtractChromeVersion_Standard(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
	got := extractChromeVersion(ua)
	if got != "134" {
		t.Errorf("extractChromeVersion = %q, want %q", got, "134")
	}
}

func TestExtractChromeVersion_OlderVersion(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.77 Safari/537.36"
	got := extractChromeVersion(ua)
	if got != "110" {
		t.Errorf("extractChromeVersion = %q, want %q", got, "110")
	}
}

func TestExtractChromeVersion_MacOS(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
	got := extractChromeVersion(ua)
	if got != "128" {
		t.Errorf("extractChromeVersion = %q, want %q", got, "128")
	}
}

func TestExtractChromeVersion_NoChrome(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
	got := extractChromeVersion(ua)
	if got != "" {
		t.Errorf("extractChromeVersion for Firefox = %q, want empty", got)
	}
}

func TestExtractChromeVersion_Empty(t *testing.T) {
	got := extractChromeVersion("")
	if got != "" {
		t.Errorf("extractChromeVersion for empty = %q, want empty", got)
	}
}

func TestExtractChromeVersion_ChromeAtEnd(t *testing.T) {
	// Chrome version at end of string with no trailing space
	ua := "SomeApp Chrome/99"
	got := extractChromeVersion(ua)
	if got != "99" {
		t.Errorf("extractChromeVersion = %q, want %q", got, "99")
	}
}

// --- extractPlatform Tests ---

func TestExtractPlatform_Windows(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
	got := extractPlatform(ua)
	if got != "Windows" {
		t.Errorf("extractPlatform = %q, want %q", got, "Windows")
	}
}

func TestExtractPlatform_MacOS(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
	got := extractPlatform(ua)
	if got != "macOS" {
		t.Errorf("extractPlatform = %q, want %q", got, "macOS")
	}
}

func TestExtractPlatform_Linux(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.77 Safari/537.36"
	got := extractPlatform(ua)
	if got != "Linux" {
		t.Errorf("extractPlatform = %q, want %q", got, "Linux")
	}
}

func TestExtractPlatform_Android(t *testing.T) {
	// Android contains "Linux" but should not match Linux platform
	ua := "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36"
	got := extractPlatform(ua)
	if got != "Windows" {
		// Android UA has "Linux" but also "Android" — defaults to Windows since it's desktop-focused
		t.Errorf("extractPlatform for Android = %q, want %q", got, "Windows")
	}
}

func TestExtractPlatform_Unknown(t *testing.T) {
	got := extractPlatform("SomeCustomAgent/1.0")
	if got != "Windows" {
		t.Errorf("extractPlatform for unknown = %q, want %q (default)", got, "Windows")
	}
}

// --- generateSecChUa Tests ---

func TestGenerateSecChUa_Chrome134(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
	got := generateSecChUa(ua)
	if !strings.Contains(got, `"Chromium";v="134"`) {
		t.Errorf("sec-ch-ua should contain Chromium v134, got %q", got)
	}
	if !strings.Contains(got, `"Google Chrome";v="134"`) {
		t.Errorf("sec-ch-ua should contain Google Chrome v134, got %q", got)
	}
	// Should contain GREASE brand
	if !strings.Contains(got, "Brand") {
		t.Errorf("sec-ch-ua should contain GREASE brand, got %q", got)
	}
}

func TestGenerateSecChUa_Chrome110(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/110.0.5481.77 Safari/537.36"
	got := generateSecChUa(ua)
	if !strings.Contains(got, `"Chromium";v="110"`) {
		t.Errorf("sec-ch-ua should contain Chromium v110, got %q", got)
	}
}

func TestGenerateSecChUa_NoChrome(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
	got := generateSecChUa(ua)
	if got != "" {
		t.Errorf("sec-ch-ua for Firefox should be empty, got %q", got)
	}
}

// --- generateSecChUaMobile Tests ---

func TestGenerateSecChUaMobile_Desktop(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36"
	got := generateSecChUaMobile(ua)
	if got != "?0" {
		t.Errorf("sec-ch-ua-mobile for desktop = %q, want %q", got, "?0")
	}
}

func TestGenerateSecChUaMobile_Mobile(t *testing.T) {
	ua := "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36"
	got := generateSecChUaMobile(ua)
	if got != "?1" {
		t.Errorf("sec-ch-ua-mobile for mobile = %q, want %q", got, "?1")
	}
}

// --- generateSecChUaPlatform Tests ---

func TestGenerateSecChUaPlatform_Windows(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36"
	got := generateSecChUaPlatform(ua)
	if got != `"Windows"` {
		t.Errorf("sec-ch-ua-platform = %q, want %q", got, `"Windows"`)
	}
}

func TestGenerateSecChUaPlatform_MacOS(t *testing.T) {
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36"
	got := generateSecChUaPlatform(ua)
	if got != `"macOS"` {
		t.Errorf("sec-ch-ua-platform = %q, want %q", got, `"macOS"`)
	}
}

func TestGenerateSecChUaPlatform_Linux(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/110.0.0.0 Safari/537.36"
	got := generateSecChUaPlatform(ua)
	if got != `"Linux"` {
		t.Errorf("sec-ch-ua-platform = %q, want %q", got, `"Linux"`)
	}
}

// --- greaseBrand Tests ---

func TestGreaseBrand_ReturnsNonEmpty(t *testing.T) {
	versions := []string{"100", "110", "120", "130", "134", "140"}
	for _, v := range versions {
		got := greaseBrand(v)
		if got == "" {
			t.Errorf("greaseBrand(%q) returned empty", v)
		}
		if !strings.Contains(got, "Brand") {
			t.Errorf("greaseBrand(%q) = %q, should contain 'Brand'", v, got)
		}
	}
}

func TestGreaseBrand_InvalidVersion(t *testing.T) {
	got := greaseBrand("abc")
	if got == "" {
		t.Error("greaseBrand with invalid version should return a default")
	}
}

// --- Constants Tests ---

func TestChromeAcceptHeader_ContainsImageFormats(t *testing.T) {
	if !strings.Contains(chromeAcceptHeader, "image/avif") {
		t.Error("chromeAcceptHeader should include image/avif")
	}
	if !strings.Contains(chromeAcceptHeader, "image/webp") {
		t.Error("chromeAcceptHeader should include image/webp")
	}
}

func TestChromeAcceptEncoding_ContainsBrotli(t *testing.T) {
	if !strings.Contains(chromeAcceptEncoding, "br") {
		t.Error("chromeAcceptEncoding should include br (Brotli)")
	}
	if !strings.Contains(chromeAcceptEncoding, "gzip") {
		t.Error("chromeAcceptEncoding should include gzip")
	}
	if !strings.Contains(chromeAcceptEncoding, "deflate") {
		t.Error("chromeAcceptEncoding should include deflate")
	}
}

// --- makeRequest Header Integration Tests ---

func TestMakeRequest_IncludesSecChUa(t *testing.T) {
	var capturedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	profile := NewHTTPProfile(ts.URL, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36", "", 1, 5, 0, false, "/test", "/test", "", "", "none", "", nil)

	resp, err := profile.makeRequest("GET", "/test", nil, nil)
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	resp.Body.Close()

	// Verify sec-ch-ua headers are present
	if capturedHeaders.Get("Sec-Ch-Ua") == "" {
		t.Error("Sec-Ch-Ua header missing")
	}
	if !strings.Contains(capturedHeaders.Get("Sec-Ch-Ua"), "134") {
		t.Errorf("Sec-Ch-Ua should contain version 134, got %q", capturedHeaders.Get("Sec-Ch-Ua"))
	}
	if capturedHeaders.Get("Sec-Ch-Ua-Mobile") != "?0" {
		t.Errorf("Sec-Ch-Ua-Mobile = %q, want ?0", capturedHeaders.Get("Sec-Ch-Ua-Mobile"))
	}
	if capturedHeaders.Get("Sec-Ch-Ua-Platform") != `"Windows"` {
		t.Errorf("Sec-Ch-Ua-Platform = %q, want \"Windows\"", capturedHeaders.Get("Sec-Ch-Ua-Platform"))
	}
}

func TestMakeRequest_IncludesUpgradeInsecureRequests(t *testing.T) {
	var capturedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	profile := NewHTTPProfile(ts.URL, "Mozilla/5.0 Chrome/134.0.0.0", "", 1, 5, 0, false, "/test", "/test", "", "", "none", "", nil)

	resp, err := profile.makeRequest("GET", "/test", nil, nil)
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	resp.Body.Close()

	if capturedHeaders.Get("Upgrade-Insecure-Requests") != "1" {
		t.Errorf("Upgrade-Insecure-Requests = %q, want %q", capturedHeaders.Get("Upgrade-Insecure-Requests"), "1")
	}
}

func TestMakeRequest_AcceptEncodingIncludesBrotli(t *testing.T) {
	var capturedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	profile := NewHTTPProfile(ts.URL, "Mozilla/5.0 Chrome/134.0.0.0", "", 1, 5, 0, false, "/test", "/test", "", "", "none", "", nil)

	resp, err := profile.makeRequest("GET", "/test", nil, nil)
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	resp.Body.Close()

	ae := capturedHeaders.Get("Accept-Encoding")
	if !strings.Contains(ae, "br") {
		t.Errorf("Accept-Encoding = %q, should contain 'br'", ae)
	}
}

func TestMakeRequest_AcceptHeaderModern(t *testing.T) {
	var capturedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	profile := NewHTTPProfile(ts.URL, "Mozilla/5.0 Chrome/134.0.0.0", "", 1, 5, 0, false, "/test", "/test", "", "", "none", "", nil)

	resp, err := profile.makeRequest("GET", "/test", nil, nil)
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	resp.Body.Close()

	accept := capturedHeaders.Get("Accept")
	if !strings.Contains(accept, "image/avif") {
		t.Errorf("Accept header should include image/avif, got %q", accept)
	}
}

func TestMakeRequest_NoSecChUaForFirefox(t *testing.T) {
	var capturedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// Firefox UA — should NOT generate sec-ch-ua headers
	profile := NewHTTPProfile(ts.URL, "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0", "", 1, 5, 0, false, "/test", "/test", "", "", "none", "", nil)

	resp, err := profile.makeRequest("GET", "/test", nil, nil)
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	resp.Body.Close()

	if capturedHeaders.Get("Sec-Ch-Ua") != "" {
		t.Errorf("Firefox UA should not have Sec-Ch-Ua, got %q", capturedHeaders.Get("Sec-Ch-Ua"))
	}
}

func TestMakeRequest_CustomHeadersOverrideNewDefaults(t *testing.T) {
	var capturedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	profile := NewHTTPProfile(ts.URL, "Mozilla/5.0 Chrome/134.0.0.0", "", 1, 5, 0, false, "/test", "/test", "", "", "none", "", nil)
	profile.CustomHeaders = map[string]string{
		"Accept-Encoding": "gzip",
		"Sec-Ch-Ua":       "custom",
	}

	resp, err := profile.makeRequest("GET", "/test", nil, nil)
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	resp.Body.Close()

	// Custom headers should override defaults
	if capturedHeaders.Get("Accept-Encoding") != "gzip" {
		t.Errorf("CustomHeaders should override Accept-Encoding, got %q", capturedHeaders.Get("Accept-Encoding"))
	}
	if capturedHeaders.Get("Sec-Ch-Ua") != "custom" {
		t.Errorf("CustomHeaders should override Sec-Ch-Ua, got %q", capturedHeaders.Get("Sec-Ch-Ua"))
	}
}

// --- readResponseBody Decompression Tests ---

func TestReadResponseBody_Brotli(t *testing.T) {
	original := []byte("Hello from a Brotli-compressed response!")
	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	if _, err := bw.Write(original); err != nil {
		t.Fatalf("brotli.Write failed: %v", err)
	}
	if err := bw.Close(); err != nil {
		t.Fatalf("brotli.Close failed: %v", err)
	}

	resp := &http.Response{
		Header: http.Header{"Content-Encoding": {"br"}},
		Body:   io.NopCloser(&buf),
	}

	got, err := readResponseBody(resp)
	if err != nil {
		t.Fatalf("readResponseBody (brotli) failed: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("readResponseBody = %q, want %q", got, original)
	}
}

func TestReadResponseBody_Gzip(t *testing.T) {
	original := []byte("Hello from a gzip-compressed response!")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(original); err != nil {
		t.Fatalf("gzip.Write failed: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip.Close failed: %v", err)
	}

	resp := &http.Response{
		Header: http.Header{"Content-Encoding": {"gzip"}},
		Body:   io.NopCloser(&buf),
	}

	got, err := readResponseBody(resp)
	if err != nil {
		t.Fatalf("readResponseBody (gzip) failed: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("readResponseBody = %q, want %q", got, original)
	}
}

func TestReadResponseBody_NoEncoding(t *testing.T) {
	original := []byte("Plain text response")
	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(bytes.NewReader(original)),
	}

	got, err := readResponseBody(resp)
	if err != nil {
		t.Fatalf("readResponseBody (none) failed: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("readResponseBody = %q, want %q", got, original)
	}
}

func TestReadResponseBody_BrotliViaServer(t *testing.T) {
	// Full round-trip test: server sends Brotli-compressed response
	original := "This is a Brotli-compressed server response for testing C2 communication"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		bw := brotli.NewWriter(&buf)
		bw.Write([]byte(original))
		bw.Close()
		w.Header().Set("Content-Encoding", "br")
		w.Write(buf.Bytes())
	}))
	defer ts.Close()

	profile := NewHTTPProfile(ts.URL, "Mozilla/5.0 Chrome/134.0.0.0", "", 1, 5, 0, false, "/test", "/test", "", "", "none", "", nil)
	resp, err := profile.makeRequest("GET", "/test", nil, nil)
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := readResponseBody(resp)
	if err != nil {
		t.Fatalf("readResponseBody failed: %v", err)
	}
	if string(body) != original {
		t.Errorf("round-trip got %q, want %q", string(body), original)
	}
}

// --- End-to-end header validation ---

func TestMakeRequest_AllChromeHeaders(t *testing.T) {
	// Comprehensive test: verify all expected Chrome headers are present
	var capturedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
	profile := NewHTTPProfile(ts.URL, ua, "", 1, 5, 0, false, "/test", "/test", "", "", "none", "", nil)

	resp, err := profile.makeRequest("POST", "/test", []byte("test body"), nil)
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	resp.Body.Close()

	checks := map[string]string{
		"User-Agent":                ua,
		"Content-Type":              "application/x-www-form-urlencoded",
		"Accept-Language":           "en-US,en;q=0.9",
		"Sec-Ch-Ua-Mobile":         "?0",
		"Sec-Ch-Ua-Platform":       `"Windows"`,
		"Upgrade-Insecure-Requests": "1",
	}
	for header, expected := range checks {
		got := capturedHeaders.Get(header)
		if got != expected {
			t.Errorf("%s = %q, want %q", header, got, expected)
		}
	}
	// Partial checks
	if !strings.Contains(capturedHeaders.Get("Accept"), "image/avif") {
		t.Error("Accept should contain image/avif")
	}
	if !strings.Contains(capturedHeaders.Get("Accept-Encoding"), "br") {
		t.Error("Accept-Encoding should contain br")
	}
	if !strings.Contains(capturedHeaders.Get("Sec-Ch-Ua"), "134") {
		t.Error("Sec-Ch-Ua should contain version 134")
	}
}
