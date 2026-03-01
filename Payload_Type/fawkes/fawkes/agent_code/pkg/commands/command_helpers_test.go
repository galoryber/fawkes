package commands

import (
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
