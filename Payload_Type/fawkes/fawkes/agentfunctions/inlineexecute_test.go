package agentfunctions

import (
	"testing"
)

func TestConvertToGoffloaderFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "empty string",
			input: "",
			want:  []string{},
		},
		{
			name:  "single string arg",
			input: "z:hostname",
			want:  []string{"zhostname"},
		},
		{
			name:  "single int arg",
			input: "i:80",
			want:  []string{"i80"},
		},
		{
			name:  "multiple args",
			input: "z:hostname i:80 b:AQIDBA==",
			want:  []string{"zhostname", "i80", "bAQIDBA=="},
		},
		{
			name:  "wide string",
			input: "Z:hello",
			want:  []string{"Zhello"},
		},
		{
			name:  "short int",
			input: "s:42",
			want:  []string{"s42"},
		},
		{
			name:  "quoted value without spaces",
			input: `z:"hello"`,
			want:  []string{"zhello"},
		},
		{
			name:  "skip NULL",
			input: "z:hostname i:NULL",
			want:  []string{"zhostname"},
		},
		{
			name:  "skip SKIP",
			input: "z:SKIP i:80",
			want:  []string{"i80"},
		},
		{
			name:    "invalid format",
			input:   "nocolon",
			wantErr: true,
		},
		{
			name:    "unknown type",
			input:   "x:value",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToGoffloaderFormat(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("convertToGoffloaderFormat(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("convertToGoffloaderFormat(%q) unexpected error: %v", tt.input, err)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("convertToGoffloaderFormat(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("convertToGoffloaderFormat(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestConvertTypedArrayToGoffloaderFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   [][]string
		want    []string
		wantErr bool
	}{
		{
			name:  "empty array",
			input: [][]string{},
			want:  nil,
		},
		{
			name:  "single string arg",
			input: [][]string{{"z", "hostname"}},
			want:  []string{"zhostname"},
		},
		{
			name:  "multiple args",
			input: [][]string{{"z", "hostname"}, {"i", "80"}, {"b", "AQIDBA=="}},
			want:  []string{"zhostname", "i80", "bAQIDBA=="},
		},
		{
			name:  "wide string",
			input: [][]string{{"Z", "hello"}},
			want:  []string{"Zhello"},
		},
		{
			name:  "Forge long type names",
			input: [][]string{{"string", "hostname"}, {"int", "80"}, {"wchar", "wide"}, {"short", "42"}, {"binary", "AQID"}},
			want:  []string{"zhostname", "i80", "Zwide", "s42", "bAQID"},
		},
		{
			name:  "int32 type name",
			input: [][]string{{"int32", "443"}},
			want:  []string{"i443"},
		},
		{
			name:  "int16 type name",
			input: [][]string{{"int16", "80"}},
			want:  []string{"s80"},
		},
		{
			name:  "base64 type name",
			input: [][]string{{"base64", "AQIDBA=="}},
			want:  []string{"bAQIDBA=="},
		},
		{
			name:  "skip short entries",
			input: [][]string{{"z"}, {"z", "hostname"}},
			want:  []string{"zhostname"},
		},
		{
			name:    "unknown type",
			input:   [][]string{{"x", "value"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertTypedArrayToGoffloaderFormat(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("convertTypedArrayToGoffloaderFormat(%v) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("convertTypedArrayToGoffloaderFormat(%v) unexpected error: %v", tt.input, err)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("convertTypedArrayToGoffloaderFormat(%v) = %v (len %d), want %v (len %d)", tt.input, got, len(got), tt.want, len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("convertTypedArrayToGoffloaderFormat(%v)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}
