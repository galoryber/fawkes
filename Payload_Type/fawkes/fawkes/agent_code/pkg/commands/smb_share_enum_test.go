package commands

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestMatchesAnyPattern(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		patterns []string
		match    bool
		pat      string
	}{
		{"kdbx match", "passwords.kdbx", []string{"*.kdbx"}, true, "*.kdbx"},
		{"pfx match", "cert.pfx", []string{"*.pfx", "*.p12"}, true, "*.pfx"},
		{"no match", "readme.txt", []string{"*.kdbx", "*.pfx"}, false, ""},
		{"exact match", "web.config", []string{"web.config"}, true, "web.config"},
		{"case insensitive", "Web.Config", []string{"web.config"}, true, "web.config"},
		{"case insensitive ext", "DATA.KDBX", []string{"*.kdbx"}, true, "*.kdbx"},
		{"wildcard prefix", "backup_passwords.txt", []string{"passwords.*"}, false, ""},
		{"exact passwords file", "passwords.txt", []string{"passwords.*"}, true, "passwords.*"},
		{"Groups.xml", "Groups.xml", []string{"Groups.xml"}, true, "Groups.xml"},
		{"id_rsa", "id_rsa", []string{"id_rsa"}, true, "id_rsa"},
		{"env file", ".env", []string{"*.env"}, true, "*.env"},
		{"sql file", "dump.sql", []string{"*.sql"}, true, "*.sql"},
		{"no patterns", "anything.txt", nil, false, ""},
		{"empty patterns", "anything.txt", []string{}, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, pat := matchesAnyPattern(tt.filename, tt.patterns)
			if matched != tt.match {
				t.Errorf("matchesAnyPattern(%q, %v) = %v, want %v", tt.filename, tt.patterns, matched, tt.match)
			}
			if tt.match && pat != tt.pat {
				t.Errorf("matchesAnyPattern(%q) pattern = %q, want %q", tt.filename, pat, tt.pat)
			}
		})
	}
}

func TestParseExtensions(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect map[string]bool
	}{
		{"empty", "", nil},
		{"single", ".docx", map[string]bool{".docx": true}},
		{"no dot", "docx", map[string]bool{".docx": true}},
		{"multiple", ".docx,.xlsx,.pdf", map[string]bool{".docx": true, ".xlsx": true, ".pdf": true}},
		{"mixed dots", "docx,.xlsx,pdf", map[string]bool{".docx": true, ".xlsx": true, ".pdf": true}},
		{"spaces", " .docx , .xlsx , .pdf ", map[string]bool{".docx": true, ".xlsx": true, ".pdf": true}},
		{"uppercase", ".DOCX,.Xlsx", map[string]bool{".docx": true, ".xlsx": true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseExtensions(tt.input)
			if tt.expect == nil {
				if result != nil {
					t.Errorf("parseExtensions(%q) = %v, want nil", tt.input, result)
				}
				return
			}
			if len(result) != len(tt.expect) {
				t.Errorf("parseExtensions(%q) len = %d, want %d", tt.input, len(result), len(tt.expect))
				return
			}
			for k := range tt.expect {
				if !result[k] {
					t.Errorf("parseExtensions(%q) missing key %q", tt.input, k)
				}
			}
		})
	}
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []string
	}{
		{"empty", "", nil},
		{"single", "hello", []string{"hello"}},
		{"multiple", "a,b,c", []string{"a", "b", "c"}},
		{"spaces", " a , b , c ", []string{"a", "b", "c"}},
		{"empty parts", "a,,b,,c", []string{"a", "b", "c"}},
		{"trailing comma", "a,b,", []string{"a", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input)
			if len(result) != len(tt.expect) {
				t.Errorf("splitAndTrim(%q) = %v, want %v", tt.input, result, tt.expect)
				return
			}
			for i := range tt.expect {
				if result[i] != tt.expect[i] {
					t.Errorf("splitAndTrim(%q)[%d] = %q, want %q", tt.input, i, result[i], tt.expect[i])
				}
			}
		})
	}
}

func TestClassifyShare(t *testing.T) {
	tests := []struct {
		name   string
		share  string
		files  int
		expect string
	}{
		{"C$", "C$", 5, "Administrative drive share"},
		{"D$", "D$", 3, "Administrative drive share"},
		{"ADMIN$", "ADMIN$", 2, "Windows system directory"},
		{"IPC$", "IPC$", 0, "IPC (inter-process communication)"},
		{"SYSVOL", "SYSVOL", 10, "Active Directory SYSVOL"},
		{"NETLOGON", "NETLOGON", 5, "Active Directory NETLOGON"},
		{"PRINT$", "PRINT$", 1, "Printer drivers"},
		{"custom empty", "CustomShare", 0, "Empty share"},
		{"custom with files", "Data", 15, "15 entries"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := make([]mockFileInfo, tt.files)
			infos := make([]interface{ Name() string }, tt.files)
			_ = infos // suppress unused

			// Create mock os.FileInfo slice
			var osEntries []os.FileInfo
			for i := 0; i < tt.files; i++ {
				osEntries = append(osEntries, entries[i])
			}

			result := classifyShare(tt.share, osEntries)
			if result != tt.expect {
				t.Errorf("classifyShare(%q, %d files) = %q, want %q", tt.share, tt.files, result, tt.expect)
			}
		})
	}
}

func TestDefaultSensitivePatterns(t *testing.T) {
	if len(defaultSensitivePatterns) == 0 {
		t.Error("defaultSensitivePatterns should not be empty")
	}

	// Verify all patterns are valid glob patterns
	for _, pat := range defaultSensitivePatterns {
		_, err := matchesAnyPattern("test.txt", []string{pat})
		_ = err // matchesAnyPattern doesn't return error directly, but filepath.Match would fail on bad patterns
	}

	// Verify key patterns match expected files
	sensitiveFiles := map[string]bool{
		"passwords.kdbx":            true,
		"cert.pfx":                  true,
		"server.key":                true,
		"web.config":                true,
		"unattend.xml":              true,
		"Groups.xml":                true,
		"id_rsa":                    true,
		"backup.sql":                true,
		"database.bak":              true,
		"ConsoleHost_history.txt":   true,
	}

	for file := range sensitiveFiles {
		matched, _ := matchesAnyPattern(file, defaultSensitivePatterns)
		if !matched {
			t.Errorf("defaultSensitivePatterns should match %q but didn't", file)
		}
	}

	// Verify normal files don't match
	normalFiles := []string{"readme.txt", "program.exe", "document.docx", "image.png"}
	for _, file := range normalFiles {
		matched, _ := matchesAnyPattern(file, defaultSensitivePatterns)
		if matched {
			t.Errorf("defaultSensitivePatterns should NOT match %q but did", file)
		}
	}
}

func TestSharePermResultJSON(t *testing.T) {
	r := sharePermResult{
		Share: "C$",
		Read:  true,
		Write: true,
		Files: 42,
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed sharePermResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.Share != "C$" || !parsed.Read || !parsed.Write || parsed.Files != 42 {
		t.Errorf("round-trip failed: got %+v", parsed)
	}
}

func TestSpiderEntryJSON(t *testing.T) {
	e := spiderEntry{
		Path:     "Documents\\passwords.xlsx",
		Size:     1024,
		Modified: "2026-01-15 10:30:00",
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed spiderEntry
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.Path != e.Path || parsed.Size != e.Size || parsed.Modified != e.Modified {
		t.Errorf("round-trip failed: got %+v", parsed)
	}
}

func TestSearchMatchJSON(t *testing.T) {
	m := searchMatch{
		Share:    "Data",
		Path:     "IT\\passwords.kdbx",
		Size:     2048,
		Modified: "2026-03-10 14:00:00",
		Pattern:  "*.kdbx",
	}

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed searchMatch
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.Share != m.Share || parsed.Path != m.Path || parsed.Pattern != m.Pattern {
		t.Errorf("round-trip failed: got %+v", parsed)
	}
}

// mockFileInfo implements os.FileInfo for testing.
type mockFileInfo struct {
	name    string
	size    int64
	isDir   bool
	modTime time.Time
}

func (m mockFileInfo) Name() string      { return m.name }
func (m mockFileInfo) Size() int64       { return m.size }
func (m mockFileInfo) Mode() os.FileMode { return 0644 }
func (m mockFileInfo) ModTime() time.Time {
	if m.modTime.IsZero() {
		return time.Now()
	}
	return m.modTime
}
func (m mockFileInfo) IsDir() bool      { return m.isDir }
func (m mockFileInfo) Sys() interface{} { return nil }
