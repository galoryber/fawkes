package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestSMB_PushActionParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAction string
		wantSource string
		wantHost   string
		wantShare  string
		wantPath   string
	}{
		{
			"push with all params",
			`{"action":"push","host":"192.168.1.1","share":"C$","path":"temp/payload.exe","source":"/tmp/payload.exe","username":"admin","password":"pass"}`,
			"push", "/tmp/payload.exe", "192.168.1.1", "C$", "temp/payload.exe",
		},
		{
			"push with ADMIN$ share",
			`{"action":"push","host":"dc01","share":"ADMIN$","path":"payload.exe","source":"/opt/tools/payload.exe","username":"admin","hash":"aad3b435b51404ee:8846f7eaee8fb117"}`,
			"push", "/opt/tools/payload.exe", "dc01", "ADMIN$", "payload.exe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args smbArgs
			if err := json.Unmarshal([]byte(tt.input), &args); err != nil {
				t.Fatalf("JSON unmarshal failed: %v", err)
			}
			if args.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", args.Action, tt.wantAction)
			}
			if args.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", args.Source, tt.wantSource)
			}
			if args.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", args.Host, tt.wantHost)
			}
			if args.Share != tt.wantShare {
				t.Errorf("Share = %q, want %q", args.Share, tt.wantShare)
			}
			if args.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", args.Path, tt.wantPath)
			}
		})
	}
}

func TestSMB_PushRequiresSource(t *testing.T) {
	cmd := &SmbCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"push","host":"192.168.1.1","share":"C$","path":"test.exe","username":"admin","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("push without source should error, got status=%q", result.Status)
	}
}

func TestSMB_PushRequiresShareAndPath(t *testing.T) {
	cmd := &SmbCommand{}
	// Missing share
	result := cmd.Execute(structs.Task{Params: `{"action":"push","host":"192.168.1.1","path":"test.exe","source":"/tmp/x","username":"admin","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("push without share should error, got status=%q", result.Status)
	}
	// Missing path
	result = cmd.Execute(structs.Task{Params: `{"action":"push","host":"192.168.1.1","share":"C$","source":"/tmp/x","username":"admin","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("push without path should error, got status=%q", result.Status)
	}
}

func TestSSH_PushActionParsing(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantAction      string
		wantSource      string
		wantDestination string
	}{
		{
			"push with all params",
			`{"action":"push","host":"192.168.1.1","username":"root","password":"pass","source":"/tmp/payload","destination":"/tmp/payload"}`,
			"push", "/tmp/payload", "/tmp/payload",
		},
		{
			"push with key auth",
			`{"action":"push","host":"server","username":"deploy","key_path":"/root/.ssh/id_rsa","source":"/opt/payload","destination":"/home/deploy/payload"}`,
			"push", "/opt/payload", "/home/deploy/payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args sshExecArgs
			if err := json.Unmarshal([]byte(tt.input), &args); err != nil {
				t.Fatalf("JSON unmarshal failed: %v", err)
			}
			if args.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", args.Action, tt.wantAction)
			}
			if args.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", args.Source, tt.wantSource)
			}
			if args.Destination != tt.wantDestination {
				t.Errorf("Destination = %q, want %q", args.Destination, tt.wantDestination)
			}
		})
	}
}

func TestSSH_PushRequiresSourceAndDest(t *testing.T) {
	cmd := &SshExecCommand{}
	// Missing source
	result := cmd.Execute(structs.Task{Params: `{"action":"push","host":"192.168.1.1","username":"root","password":"pass","destination":"/tmp/x"}`})
	if result.Status != "error" {
		t.Errorf("push without source should error, got status=%q", result.Status)
	}
	// Missing destination
	result = cmd.Execute(structs.Task{Params: `{"action":"push","host":"192.168.1.1","username":"root","password":"pass","source":"/tmp/x"}`})
	if result.Status != "error" {
		t.Errorf("push without destination should error, got status=%q", result.Status)
	}
}

func TestSSH_UnknownAction(t *testing.T) {
	cmd := &SshExecCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"badaction","host":"192.168.1.1","username":"root","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("unknown action should error, got status=%q", result.Status)
	}
}

func TestSSH_ExecStillRequiresCommand(t *testing.T) {
	cmd := &SshExecCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"exec","host":"192.168.1.1","username":"root","password":"pass"}`})
	if result.Status != "error" {
		t.Errorf("exec without command should error, got status=%q", result.Status)
	}
}
