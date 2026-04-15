package http

import (
	"testing"
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
