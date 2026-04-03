//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestLastLoginEntry_StructInit(t *testing.T) {
	tests := []struct {
		name  string
		entry lastLoginEntry
		want  lastLoginEntry
	}{
		{
			name: "full entry",
			entry: lastLoginEntry{
				User:      `CORP\jsmith`,
				TTY:       "Interactive",
				From:      "192.168.1.100",
				LoginTime: "2025-06-15T10:30:00.000Z",
				Duration:  "01:23:45",
			},
			want: lastLoginEntry{
				User:      `CORP\jsmith`,
				TTY:       "Interactive",
				From:      "192.168.1.100",
				LoginTime: "2025-06-15T10:30:00.000Z",
				Duration:  "01:23:45",
			},
		},
		{
			name:  "zero value",
			entry: lastLoginEntry{},
			want:  lastLoginEntry{},
		},
		{
			name: "no duration (omitempty)",
			entry: lastLoginEntry{
				User:      "admin",
				TTY:       "Network",
				From:      "-",
				LoginTime: "2025-06-15T08:00:00.000Z",
			},
			want: lastLoginEntry{
				User:      "admin",
				TTY:       "Network",
				From:      "-",
				LoginTime: "2025-06-15T08:00:00.000Z",
			},
		},
		{
			name: "failed login entry",
			entry: lastLoginEntry{
				User:      `DOMAIN\badactor`,
				TTY:       "-",
				From:      "10.0.0.50",
				LoginTime: "2025-06-15T03:00:00.000Z",
				Duration:  "FAILED",
			},
			want: lastLoginEntry{
				User:      `DOMAIN\badactor`,
				TTY:       "-",
				From:      "10.0.0.50",
				LoginTime: "2025-06-15T03:00:00.000Z",
				Duration:  "FAILED",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.entry.User != tc.want.User {
				t.Errorf("User: got %q, want %q", tc.entry.User, tc.want.User)
			}
			if tc.entry.TTY != tc.want.TTY {
				t.Errorf("TTY: got %q, want %q", tc.entry.TTY, tc.want.TTY)
			}
			if tc.entry.From != tc.want.From {
				t.Errorf("From: got %q, want %q", tc.entry.From, tc.want.From)
			}
			if tc.entry.LoginTime != tc.want.LoginTime {
				t.Errorf("LoginTime: got %q, want %q", tc.entry.LoginTime, tc.want.LoginTime)
			}
			if tc.entry.Duration != tc.want.Duration {
				t.Errorf("Duration: got %q, want %q", tc.entry.Duration, tc.want.Duration)
			}
		})
	}
}

func TestLastLoginEntry_JSONOmitempty(t *testing.T) {
	entry := lastLoginEntry{
		User:      "admin",
		TTY:       "Interactive",
		From:      "-",
		LoginTime: "2025-06-15T08:00:00.000Z",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	jsonStr := string(data)
	// Duration has omitempty, so it should not appear when empty
	if contains(jsonStr, `"duration"`) {
		t.Errorf("expected duration to be omitted from JSON, got: %s", jsonStr)
	}

	entry.Duration = "FAILED"
	data, err = json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	jsonStr = string(data)
	if !contains(jsonStr, `"duration":"FAILED"`) {
		t.Errorf("expected duration in JSON when set, got: %s", jsonStr)
	}
}

func TestLastArgs_JSONParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    lastArgs
		wantErr bool
	}{
		{
			name:  "all fields",
			input: `{"action":"failed","count":10,"user":"admin"}`,
			want:  lastArgs{Action: "failed", Count: 10, User: "admin"},
		},
		{
			name:  "defaults (empty JSON)",
			input: `{}`,
			want:  lastArgs{},
		},
		{
			name:  "only action",
			input: `{"action":"reboot"}`,
			want:  lastArgs{Action: "reboot"},
		},
		{
			name:  "only count",
			input: `{"count":50}`,
			want:  lastArgs{Count: 50},
		},
		{
			name:  "logins action with user filter",
			input: `{"action":"logins","user":"CORP\\jsmith","count":5}`,
			want:  lastArgs{Action: "logins", User: `CORP\jsmith`, Count: 5},
		},
		{
			name:    "invalid JSON",
			input:   `{not json}`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got lastArgs
			err := json.Unmarshal([]byte(tc.input), &got)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
					return // unreachable, helps staticcheck
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Action != tc.want.Action {
				t.Errorf("Action: got %q, want %q", got.Action, tc.want.Action)
			}
			if got.Count != tc.want.Count {
				t.Errorf("Count: got %d, want %d", got.Count, tc.want.Count)
			}
			if got.User != tc.want.User {
				t.Errorf("User: got %q, want %q", got.User, tc.want.User)
			}
		})
	}
}

func TestExtractXMLField_LastWindows(t *testing.T) {
	tests := []struct {
		name  string
		xml   string
		field string
		want  string
	}{
		{
			name:  "simple element",
			xml:   `<Event><EventID>4624</EventID></Event>`,
			field: "EventID",
			want:  "4624",
		},
		{
			name:  "element with attributes",
			xml:   `<EventID Qualifiers='0'>4625</EventID>`,
			field: "EventID",
			want:  "4625",
		},
		{
			name:  "target user name",
			xml:   `<Data Name='TargetUserName'>jsmith</Data><TargetUserName>admin</TargetUserName>`,
			field: "TargetUserName",
			want:  "admin",
		},
		{
			name:  "field not present",
			xml:   `<Event><EventID>4624</EventID></Event>`,
			field: "MissingField",
			want:  "",
		},
		{
			name:  "empty element",
			xml:   `<TargetUserName></TargetUserName>`,
			field: "TargetUserName",
			want:  "",
		},
		{
			name:  "nested in larger XML",
			xml:   `<Event><System><EventID>1074</EventID><Level>4</Level></System></Event>`,
			field: "Level",
			want:  "4",
		},
		{
			name:  "logon type value",
			xml:   `<Data><LogonType>10</LogonType></Data>`,
			field: "LogonType",
			want:  "10",
		},
		{
			name:  "IP address field",
			xml:   `<IpAddress>192.168.1.100</IpAddress>`,
			field: "IpAddress",
			want:  "192.168.1.100",
		},
		{
			name:  "dash value",
			xml:   `<IpAddress>-</IpAddress>`,
			field: "IpAddress",
			want:  "-",
		},
		{
			name:  "domain name",
			xml:   `<TargetDomainName>CORP</TargetDomainName>`,
			field: "TargetDomainName",
			want:  "CORP",
		},
		{
			name:  "empty XML string",
			xml:   "",
			field: "EventID",
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractXMLField(tc.xml, tc.field)
			if got != tc.want {
				t.Errorf("extractXMLField(%q, %q) = %q, want %q", tc.xml, tc.field, got, tc.want)
			}
		})
	}
}

func TestExtractXMLAttr_LastWindows(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		element string
		attr    string
		want    string
	}{
		{
			name:    "single-quoted attribute",
			xml:     `<TimeCreated SystemTime='2025-06-15T10:30:00.000Z'/>`,
			element: "TimeCreated",
			attr:    "SystemTime",
			want:    "2025-06-15T10:30:00.000Z",
		},
		{
			name:    "double-quoted attribute",
			xml:     `<TimeCreated SystemTime="2025-06-15T10:30:00.000Z"/>`,
			element: "TimeCreated",
			attr:    "SystemTime",
			want:    "2025-06-15T10:30:00.000Z",
		},
		{
			name:    "provider name attribute",
			xml:     `<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>`,
			element: "Provider",
			attr:    "Name",
			want:    "Microsoft-Windows-Security-Auditing",
		},
		{
			name:    "GUID attribute",
			xml:     `<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>`,
			element: "Provider",
			attr:    "Guid",
			want:    "{54849625-5478-4994-a5ba-3e3b0328c30d}",
		},
		{
			name:    "element not present",
			xml:     `<Event><System></System></Event>`,
			element: "TimeCreated",
			attr:    "SystemTime",
			want:    "",
		},
		{
			name:    "attribute not present on element",
			xml:     `<TimeCreated SystemTime='2025-06-15T10:30:00.000Z'/>`,
			element: "TimeCreated",
			attr:    "MissingAttr",
			want:    "",
		},
		{
			name:    "empty XML",
			xml:     "",
			element: "TimeCreated",
			attr:    "SystemTime",
			want:    "",
		},
		{
			name: "attribute in realistic event XML",
			xml: `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>` +
				`<System><Provider Name='Microsoft-Windows-Security-Auditing'/>` +
				`<EventID>4624</EventID>` +
				`<TimeCreated SystemTime='2025-06-15T10:30:00.123456789Z'/>` +
				`</System></Event>`,
			element: "TimeCreated",
			attr:    "SystemTime",
			want:    "2025-06-15T10:30:00.123456789Z",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractXMLAttr(tc.xml, tc.element, tc.attr)
			if got != tc.want {
				t.Errorf("extractXMLAttr(%q, %q, %q) = %q, want %q",
					tc.xml, tc.element, tc.attr, got, tc.want)
			}
		})
	}
}

func TestLogonTypeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2", "Interactive"},
		{"3", "Network"},
		{"7", "Unlock"},
		{"10", "RemoteDP"},
		{"11", "CachedInt"},
		{"5", "Type5"},
		{"99", "Type99"},
		{"", "Type"},
	}

	for _, tc := range tests {
		t.Run("logonType_"+tc.input, func(t *testing.T) {
			got := logonTypeName(tc.input)
			if got != tc.want {
				t.Errorf("logonTypeName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestRebootEventName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"6005", "boot"},
		{"6006", "shutdown"},
		{"6008", "crash"},
		{"1074", "restart"},
		{"9999", ""},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run("eventID_"+tc.input, func(t *testing.T) {
			got := rebootEventName(tc.input)
			if got != tc.want {
				t.Errorf("rebootEventName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
