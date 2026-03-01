package commands

import (
	"strings"
	"testing"
)

// --- DPAPI helper tests ---

func TestDpapiIsPrintable(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"normal text", []byte("Hello, World!"), true},
		{"with newline", []byte("line1\nline2"), true},
		{"with tab", []byte("col1\tcol2"), true},
		{"with carriage return", []byte("line1\r\nline2"), true},
		{"null byte", []byte{0x00}, false},
		{"control char", []byte{0x01, 0x41}, false},
		{"bell char", []byte{0x07}, false},
		{"binary data", []byte{0xFF, 0xFE, 0x01}, false},
		{"empty", []byte{}, true},
		{"space only", []byte(" "), true},
		{"tilde", []byte("~"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dpapiIsPrintable(tt.data)
			if result != tt.expected {
				t.Errorf("dpapiIsPrintable(%q) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestIsGUID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid lowercase", "12345678-abcd-ef01-2345-678901234567", true},
		{"valid uppercase", "12345678-ABCD-EF01-2345-678901234567", true},
		{"valid mixed", "A1B2C3D4-E5F6-7890-ABCD-EF1234567890", true},
		{"all zeros", "00000000-0000-0000-0000-000000000000", true},
		{"too short", "12345678-abcd-ef01-2345", false},
		{"too long", "12345678-abcd-ef01-2345-6789012345678", false},
		{"missing dash", "12345678abcd-ef01-2345-678901234567", false},
		{"wrong dash position", "1234567-8abcd-ef01-2345-678901234567", false},
		{"invalid hex char", "12345678-abcd-ef01-2345-67890123456g", false},
		{"empty", "", false},
		{"with braces", "{12345678-abcd-ef01-2345-678901234567}", false},
		{"spaces", "12345678-abcd-ef01-2345-67890123456 ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isGUID(tt.input)
			if result != tt.expected {
				t.Errorf("isGUID(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractXMLTag(t *testing.T) {
	tests := []struct {
		name     string
		xml      string
		tag      string
		expected string
	}{
		{"simple tag", "<name>John</name>", "name", "John"},
		{"nested in larger XML", "<root><user>admin</user></root>", "user", "admin"},
		{"empty value", "<key></key>", "key", ""},
		{"tag not found", "<foo>bar</foo>", "baz", ""},
		{"no closing tag", "<tag>value", "tag", ""},
		{"multiple same tags", "<a>first</a><a>second</a>", "a", "first"},
		{"tag with spaces in value", "<path>C:\\Program Files\\App</path>", "path", "C:\\Program Files\\App"},
		{"numeric value", "<count>42</count>", "count", "42"},
		{"empty string", "", "tag", ""},
		{"XML with attributes", "<event id='1'>data</event>", "event id='1'", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractXMLTag(tt.xml, tt.tag)
			if result != tt.expected {
				t.Errorf("extractXMLTag(%q, %q) = %q, want %q", tt.xml, tt.tag, result, tt.expected)
			}
		})
	}
}

// --- ETW helper tests ---

func TestClassifySessionSecurity(t *testing.T) {
	tests := []struct {
		name     string
		session  string
		expected string
	}{
		{"Windows Defender", "Microsoft-Windows-Windows Defender", "!! DEFENDER/AV"},
		{"Antimalware", "Microsoft-Antimalware-Engine", "!! DEFENDER/AV"},
		{"Sysmon", "Microsoft-Windows-Sysmon", "!! SYSMON"},
		{"CrowdStrike", "CrowdStrike Falcon Sensor", "!! EDR"},
		{"SentinelOne", "SentinelOne Agent", "!! EDR"},
		{"Carbon Black", "Carbon Black Defense", "!! EDR"},
		{"Security audit", "Microsoft-Windows-Security-Auditing", "! Security"},
		{"Audit policy", "AuditPolicyChange", "! Audit"},
		{"EventLog", "Microsoft-Windows-EventLog", "Telemetry"},
		{"ETW session", "ETW Session Autologger", "Telemetry"},
		{"Kernel", "NT Kernel Logger", "Kernel"},
		{"DiagTrack", "DiagTrack-Listener", "Diagnostics"},
		{"AutoLogger", "AutoLogger-DiagLog", "Diagnostics"},
		{"Generic session", "MyApp-Tracing", ""},
		{"Empty", "", ""},
		{"Case insensitive", "WINDOWS DEFENDER SERVICE", "!! DEFENDER/AV"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifySessionSecurity(tt.session)
			if result != tt.expected {
				t.Errorf("classifySessionSecurity(%q) = %q, want %q", tt.session, result, tt.expected)
			}
		})
	}
}

// --- BITS helper tests ---

func TestBitsFormatBytes(t *testing.T) {
	tests := []struct {
		name     string
		bytes    uint64
		expected string
	}{
		{"zero", 0, "0 B"},
		{"bytes", 512, "512 B"},
		{"kilobytes", 1024, "1.0 KB"},
		{"kilobytes fractional", 1536, "1.5 KB"},
		{"megabytes", 1048576, "1.0 MB"},
		{"megabytes fractional", 1572864, "1.5 MB"},
		{"gigabytes", 1073741824, "1.0 GB"},
		{"large", 5368709120, "5.0 GB"},
		{"just under KB", 1023, "1023 B"},
		{"just under MB", 1048575, "1024.0 KB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bitsFormatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("bitsFormatBytes(%d) = %q, want %q", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestBitsEllipsis(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncated", "hello world", 8, "hello..."},
		{"very long", "abcdefghijklmnop", 10, "abcdefg..."},
		{"empty", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bitsEllipsis(tt.input, tt.max)
			if result != tt.expected {
				t.Errorf("bitsEllipsis(%q, %d) = %q, want %q", tt.input, tt.max, result, tt.expected)
			}
		})
	}
}

// --- Credential Manager helper tests ---

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"normal text", "Hello World", true},
		{"with punctuation", "P@ssw0rd!", true},
		{"with null", "test\x00", false},
		{"with control char", "test\x01more", false},
		{"with DEL", "test\x7fmore", false},
		{"empty string", "", false},
		{"space only", " ", true},
		{"tilde", "~", true},
		{"unicode", "Hello \u00e9", true},
		{"tab", "col1\tcol2", false}, // tab is < 0x20
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrintable(tt.input)
			if result != tt.expected {
				t.Errorf("isPrintable(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCredTypeName(t *testing.T) {
	tests := []struct {
		ctype    uint32
		expected string
	}{
		{1, "Generic"},
		{2, "Domain Password"},
		{3, "Domain Certificate"},
		{4, "Domain Visible Password"},
		{0, "Unknown (0)"},
		{99, "Unknown (99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := credTypeName(tt.ctype)
			if result != tt.expected {
				t.Errorf("credTypeName(%d) = %q, want %q", tt.ctype, result, tt.expected)
			}
		})
	}
}

func TestCredPersistName(t *testing.T) {
	tests := []struct {
		persist  uint32
		expected string
	}{
		{1, "Session"},
		{2, "Local Machine"},
		{3, "Enterprise"},
		{0, "Unknown (0)"},
		{99, "Unknown (99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := credPersistName(tt.persist)
			if result != tt.expected {
				t.Errorf("credPersistName(%d) = %q, want %q", tt.persist, result, tt.expected)
			}
		})
	}
}

// --- Amcache/Shimcache helper tests ---

func TestDecodeUTF16LEShim(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"ASCII text", []byte{'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0}, "Hello"},
		{"with null terminator", []byte{'A', 0, 'B', 0, 0, 0}, "AB"},
		{"empty", []byte{}, ""},
		{"single byte", []byte{0x41}, ""},
		{"Windows path", []byte{
			'C', 0, ':', 0, '\\', 0, 'W', 0, 'i', 0, 'n', 0, 'd', 0, 'o', 0, 'w', 0, 's', 0,
		}, `C:\Windows`},
		{"unicode char", []byte{0xE9, 0x00}, "\u00e9"}, // é
		{"multiple nulls at end", []byte{'X', 0, 0, 0, 0, 0}, "X"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeUTF16LEShim(tt.input)
			if result != tt.expected {
				t.Errorf("decodeUTF16LEShim(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// filetimeToTime is tested in laps_test.go

// --- Event Log helper tests ---

func TestExtractXMLField(t *testing.T) {
	tests := []struct {
		name     string
		xml      string
		field    string
		expected string
	}{
		{"simple field", "<EventID>4624</EventID>", "EventID", "4624"},
		{"field with attributes", "<EventID Qualifiers='0'>1102</EventID>", "EventID", "1102"},
		{"nested field", "<System><Level>4</Level></System>", "Level", "4"},
		{"missing field", "<EventID>4624</EventID>", "Level", ""},
		{"empty XML", "", "EventID", ""},
		{"field with spaces", "<Data>hello world</Data>", "Data", "hello world"},
		{"empty value", "<Data></Data>", "Data", ""},
		{"no closing tag", "<EventID>4624", "EventID", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractXMLField(tt.xml, tt.field)
			if result != tt.expected {
				t.Errorf("extractXMLField(%q, %q) = %q, want %q", tt.xml, tt.field, result, tt.expected)
			}
		})
	}
}

func TestExtractXMLAttr(t *testing.T) {
	tests := []struct {
		name     string
		xml      string
		element  string
		attr     string
		expected string
	}{
		{"single-quoted attr", "<TimeCreated SystemTime='2025-01-15T12:00:00Z'/>", "TimeCreated", "SystemTime", "2025-01-15T12:00:00Z"},
		{"double-quoted attr", `<Provider Name="TestProvider"/>`, "Provider", "Name", "TestProvider"},
		{"element not found", "<Foo Bar='baz'/>", "Missing", "Bar", ""},
		{"attr not found", "<Foo Bar='baz'/>", "Foo", "Missing", ""},
		{"empty XML", "", "Foo", "Bar", ""},
		{"attr in larger XML", "<System><Provider Name='Security'/><EventID>4624</EventID></System>", "Provider", "Name", "Security"},
		{"multiple attrs", "<Event Computer='DC01' Domain='test.local'/>", "Event", "Computer", "DC01"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractXMLAttr(tt.xml, tt.element, tt.attr)
			if result != tt.expected {
				t.Errorf("extractXMLAttr(%q, %q, %q) = %q, want %q", tt.xml, tt.element, tt.attr, result, tt.expected)
			}
		})
	}
}

func TestSummarizeEventXML(t *testing.T) {
	tests := []struct {
		name     string
		xml      string
		contains []string
	}{
		{
			"full event XML",
			`<Event><System><Provider Name='Security'/><EventID>4624</EventID><Level>4</Level><TimeCreated SystemTime='2025-01-15T12:00:00.123Z'/></System></Event>`,
			[]string{"EventID: 4624", "Info", "Security", "2025-01-15T12:00:0"},
		},
		{
			"critical level",
			`<Event><System><Provider Name='Test'/><EventID>1</EventID><Level>1</Level><TimeCreated SystemTime='2025-06-01T00:00:00Z'/></System></Event>`,
			[]string{"Critical"},
		},
		{
			"error level",
			`<Event><System><Provider Name='Test'/><EventID>2</EventID><Level>2</Level><TimeCreated SystemTime='2025-06-01T00:00:00Z'/></System></Event>`,
			[]string{"Error"},
		},
		{
			"warning level",
			`<Event><System><Provider Name='Test'/><EventID>3</EventID><Level>3</Level><TimeCreated SystemTime='2025-06-01T00:00:00Z'/></System></Event>`,
			[]string{"Warning"},
		},
		{
			"verbose level",
			`<Event><System><Provider Name='Test'/><EventID>5</EventID><Level>5</Level><TimeCreated SystemTime='2025-06-01T00:00:00Z'/></System></Event>`,
			[]string{"Verbose"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := summarizeEventXML(tt.xml)
			for _, expected := range tt.contains {
				if !strings.Contains(result, expected) {
					t.Errorf("summarizeEventXML() = %q, missing %q", result, expected)
				}
			}
		})
	}
}

func TestBuildEventXPath(t *testing.T) {
	tests := []struct {
		name     string
		filter   string
		eventID  int
		expected string
	}{
		{"no filter no eventID", "", 0, "*"},
		{"eventID only", "", 4624, "*[System[EventID=4624]]"},
		{"time filter", "24h", 0, "*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"},
		{"eventID and time", "1h", 4625, "*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= 3600000]]]"},
		{"raw XPath passthrough", "*[System[Level=1]]", 0, "*[System[Level=1]]"},
		{"QueryList passthrough", "<QueryList><Query>...</Query></QueryList>", 0, "<QueryList><Query>...</Query></QueryList>"},
		{"non-time filter ignored", "keyword", 0, "*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildEventXPath(tt.filter, tt.eventID)
			if result != tt.expected {
				t.Errorf("buildEventXPath(%q, %d) = %q, want %q", tt.filter, tt.eventID, result, tt.expected)
			}
		})
	}
}

func TestFormatEvtLogSize(t *testing.T) {
	tests := []struct {
		name     string
		bytes    uint64
		expected string
	}{
		{"zero", 0, "0 B"},
		{"bytes", 512, "512 B"},
		{"KB", 1024, "1.0 KB"},
		{"MB", 1048576, "1.0 MB"},
		{"GB", 1073741824, "1.0 GB"},
		{"fractional KB", 1536, "1.5 KB"},
		{"large MB", 20971520, "20.0 MB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatEvtLogSize(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatEvtLogSize(%d) = %q, want %q", tt.bytes, result, tt.expected)
			}
		})
	}
}

// --- Scheduled Task helper tests ---

func TestTriggerTypeFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"ONLOGON", TASK_TRIGGER_LOGON},
		{"onlogon", TASK_TRIGGER_LOGON},
		{"ONSTART", TASK_TRIGGER_BOOT},
		{"DAILY", TASK_TRIGGER_DAILY},
		{"WEEKLY", TASK_TRIGGER_WEEKLY},
		{"ONIDLE", TASK_TRIGGER_IDLE},
		{"ONCE", TASK_TRIGGER_TIME},
		{"unknown", TASK_TRIGGER_LOGON},
		{"", TASK_TRIGGER_LOGON},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := triggerTypeFromString(tt.input)
			if result != tt.expected {
				t.Errorf("triggerTypeFromString(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEscapeXML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no escaping needed", "hello world", "hello world"},
		{"ampersand", "a & b", "a &amp; b"},
		{"less than", "a < b", "a &lt; b"},
		{"greater than", "a > b", "a &gt; b"},
		{"double quote", `say "hello"`, "say &quot;hello&quot;"},
		{"all special chars", `<a & "b">`, "&lt;a &amp; &quot;b&quot;&gt;"},
		{"empty", "", ""},
		{"path", `C:\Windows\System32\cmd.exe`, `C:\Windows\System32\cmd.exe`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeXML(tt.input)
			if result != tt.expected {
				t.Errorf("escapeXML(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBuildTriggerXML(t *testing.T) {
	tests := []struct {
		name    string
		trigger string
		time    string
		check   func(string) bool
	}{
		{"logon trigger", "ONLOGON", "", func(s string) bool {
			return strings.Contains(s, "<LogonTrigger>") && strings.Contains(s, "<Enabled>true</Enabled>")
		}},
		{"boot trigger", "ONSTART", "", func(s string) bool {
			return strings.Contains(s, "<BootTrigger>")
		}},
		{"idle trigger", "ONIDLE", "", func(s string) bool {
			return strings.Contains(s, "<IdleTrigger>")
		}},
		{"daily default time", "DAILY", "", func(s string) bool {
			return strings.Contains(s, "<CalendarTrigger>") && strings.Contains(s, "T09:00:00") && strings.Contains(s, "<DaysInterval>1</DaysInterval>")
		}},
		{"daily custom time", "DAILY", "14:30", func(s string) bool {
			return strings.Contains(s, "T14:30:00")
		}},
		{"weekly trigger", "WEEKLY", "", func(s string) bool {
			return strings.Contains(s, "<WeeksInterval>1</WeeksInterval>") && strings.Contains(s, "<Monday />")
		}},
		{"once trigger", "ONCE", "", func(s string) bool {
			return strings.Contains(s, "<TimeTrigger>")
		}},
		{"once custom time", "ONCE", "23:00", func(s string) bool {
			return strings.Contains(s, "T23:00:00")
		}},
		{"unknown defaults to logon", "INVALID", "", func(s string) bool {
			return strings.Contains(s, "<LogonTrigger>")
		}},
		{"case insensitive", "daily", "", func(s string) bool {
			return strings.Contains(s, "<CalendarTrigger>")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildTriggerXML(tt.trigger, tt.time)
			if !tt.check(result) {
				t.Errorf("buildTriggerXML(%q, %q) = %q, failed check", tt.trigger, tt.time, result)
			}
		})
	}
}

// --- Firewall helper tests ---

func TestFwDirectionToString(t *testing.T) {
	tests := []struct {
		dir      int
		expected string
	}{
		{fwRuleDirectionIn, "In"},
		{fwRuleDirectionOut, "Out"},
		{99, "99"},
		{0, "0"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := fwDirectionToString(tt.dir)
			if result != tt.expected {
				t.Errorf("fwDirectionToString(%d) = %q, want %q", tt.dir, result, tt.expected)
			}
		})
	}
}

func TestFwActionIntToString(t *testing.T) {
	tests := []struct {
		action   int
		expected string
	}{
		{fwActionBlock, "Block"},
		{fwActionAllow, "Allow"},
		{99, "99"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := fwActionIntToString(tt.action)
			if result != tt.expected {
				t.Errorf("fwActionIntToString(%d) = %q, want %q", tt.action, result, tt.expected)
			}
		})
	}
}

func TestFwProtocolToString(t *testing.T) {
	tests := []struct {
		proto    int
		expected string
	}{
		{fwIPProtocolTCP, "TCP"},
		{fwIPProtocolUDP, "UDP"},
		{fwIPProtocolAny, "Any"},
		{1, "ICMPv4"},
		{58, "ICMPv6"},
		{47, "47"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := fwProtocolToString(tt.proto)
			if result != tt.expected {
				t.Errorf("fwProtocolToString(%d) = %q, want %q", tt.proto, result, tt.expected)
			}
		})
	}
}

// Clipboard helpers (detectCredPatterns, formatClipEntries) tested in clipboard_test.go

// --- Credential harvest helper tests ---

func TestCredIndentLines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		prefix   string
		expected string
	}{
		{"single line", "hello", "  ", "  hello"},
		{"multi line", "line1\nline2\nline3", "    ", "    line1\n    line2\n    line3"},
		{"empty lines preserved", "a\n\nb", "  ", "  a\n\n  b"},
		{"empty string", "", "  ", ""},
		{"no prefix", "hello", "", "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := credIndentLines(tt.input, tt.prefix)
			if result != tt.expected {
				t.Errorf("credIndentLines(%q, %q) = %q, want %q", tt.input, tt.prefix, result, tt.expected)
			}
		})
	}
}

// --- WMI Persist helper tests ---

func TestBuildWQLTrigger(t *testing.T) {
	tests := []struct {
		name        string
		trigger     string
		intervalSec int
		processName string
		wantErr     bool
		contains    string
	}{
		{"logon", "logon", 0, "", false, "Win32_LogonSession"},
		{"startup", "startup", 0, "", false, "SystemUpTime"},
		{"interval", "interval", 0, "", false, "TimerEvent"},
		{"process with name", "process", 0, "notepad.exe", false, "notepad.exe"},
		{"process no name", "process", 0, "", true, ""},
		{"unknown trigger", "invalid", 0, "", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildWQLTrigger(tt.trigger, tt.intervalSec, tt.processName)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if !strings.Contains(result, tt.contains) {
				t.Errorf("buildWQLTrigger() = %q, missing %q", result, tt.contains)
			}
		})
	}
}
