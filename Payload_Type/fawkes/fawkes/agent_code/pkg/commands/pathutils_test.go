package commands

import "testing"

func TestStripPathQuotes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"no quotes", "C:\\Windows\\System32", "C:\\Windows\\System32"},
		{"double quotes", `"C:\Program Files"`, "C:\\Program Files"},
		{"single quotes", `'C:\Program Files'`, "C:\\Program Files"},
		{"leading/trailing whitespace", "  C:\\Windows  ", "C:\\Windows"},
		{"whitespace with double quotes", `  "C:\Program Files"  `, "C:\\Program Files"},
		{"whitespace with single quotes", `  'C:\Program Files'  `, "C:\\Program Files"},
		{"single char", "a", "a"},
		{"two chars no quotes", "ab", "ab"},
		{"mismatched quotes double-single", `"test'`, `"test'`},
		{"mismatched quotes single-double", `'test"`, `'test"`},
		{"only double quotes", `""`, ""},
		{"only single quotes", `''`, ""},
		{"unix path", "/home/user/file.txt", "/home/user/file.txt"},
		{"unix path quoted", `"/home/user/my file.txt"`, "/home/user/my file.txt"},
		{"inner quotes preserved", `"he said 'hello'"`, `he said 'hello'`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := stripPathQuotes(tc.input)
			if result != tc.expected {
				t.Errorf("stripPathQuotes(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}
