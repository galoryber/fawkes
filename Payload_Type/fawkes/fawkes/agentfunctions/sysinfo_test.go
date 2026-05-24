package agentfunctions

import "testing"

func TestExtractField(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		prefix string
		want   string
	}{
		{"match with spaces", "Hostname: DESKTOP-ABC", "Hostname:", "DESKTOP-ABC"},
		{"match trimmed", "OS:   Windows 11  ", "OS:", "Windows 11"},
		{"no match", "Architecture: amd64", "Hostname:", ""},
		{"empty line", "", "Hostname:", ""},
		{"empty prefix", "anything", "", "anything"},
		{"prefix only", "Hostname:", "Hostname:", ""},
		{"case sensitive miss", "hostname: test", "Hostname:", ""},
		{"partial prefix", "HostnameExtra: val", "Hostname:", ""},
		{"prefix with colon space", "PID: 1234", "PID:", "1234"},
		{"value with colons", "Domain: corp.example.com:389", "Domain:", "corp.example.com:389"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractField(tt.line, tt.prefix)
			if got != tt.want {
				t.Errorf("extractField(%q, %q) = %q, want %q", tt.line, tt.prefix, got, tt.want)
			}
		})
	}
}
