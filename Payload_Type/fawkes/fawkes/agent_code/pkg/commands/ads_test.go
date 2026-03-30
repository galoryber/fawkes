//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestAdsArgs_JSONParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAction string
		wantFile   string
		wantStream string
		wantHex    bool
		wantErr    bool
	}{
		{"write", `{"action":"write","file":"C:\\test.txt","stream":"hidden","data":"secret"}`, "write", "C:\\test.txt", "hidden", false, false},
		{"read", `{"action":"read","file":"C:\\test.txt","stream":"hidden"}`, "read", "C:\\test.txt", "hidden", false, false},
		{"list", `{"action":"list","file":"C:\\test.txt"}`, "list", "C:\\test.txt", "", false, false},
		{"delete", `{"action":"delete","file":"C:\\test.txt","stream":"hidden"}`, "delete", "C:\\test.txt", "hidden", false, false},
		{"hex mode", `{"action":"write","file":"test.exe","stream":"data","data":"4d5a","hex":true}`, "write", "test.exe", "data", true, false},
		{"empty", `{}`, "", "", "", false, false},
		{"invalid", `{bad`, "", "", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args adsArgs
			err := json.Unmarshal([]byte(tt.input), &args)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if args.Action != tt.wantAction {
					t.Errorf("Action = %q, want %q", args.Action, tt.wantAction)
				}
				if args.File != tt.wantFile {
					t.Errorf("File = %q, want %q", args.File, tt.wantFile)
				}
				if args.Stream != tt.wantStream {
					t.Errorf("Stream = %q, want %q", args.Stream, tt.wantStream)
				}
				if args.Hex != tt.wantHex {
					t.Errorf("Hex = %v, want %v", args.Hex, tt.wantHex)
				}
			}
		})
	}
}

func TestADSCommand_Name(t *testing.T) {
	cmd := &ADSCommand{}
	if cmd.Name() != "ads" {
		t.Errorf("Name() = %q, want ads", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}
