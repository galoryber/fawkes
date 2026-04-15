package http

type TrafficProfile struct {
	Name         string
	GetPaths     []string
	PostPaths    []string
	ContentTypes []string
	Headers      map[string]string
	UserAgents   []string
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

	return true
}
