package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestSSHTunnelListEmpty(t *testing.T) {
	result := sshTunnelList()
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if result.Output != "No active SSH tunnels" {
		t.Errorf("expected 'No active SSH tunnels', got %q", result.Output)
	}
}

func TestSSHTunnelStopNonExistent(t *testing.T) {
	result := sshTunnelStop("nonexistent-tunnel-id")
	if result.Status != "error" {
		t.Errorf("expected error for non-existent tunnel, got %s", result.Status)
	}
}

func TestSSHTunnelLocalValidation(t *testing.T) {
	cmd := &SshExecCommand{}

	tests := []struct {
		name   string
		params sshExecArgs
		errMsg string
	}{
		{
			name: "missing local_port",
			params: sshExecArgs{
				Host: "1.2.3.4", Username: "user", Password: "pass",
				Action: "tunnel-local", RemoteHost: "target", RemotePort: 80,
			},
			errMsg: "local_port",
		},
		{
			name: "missing remote_host",
			params: sshExecArgs{
				Host: "1.2.3.4", Username: "user", Password: "pass",
				Action: "tunnel-local", LocalPort: 8080, RemotePort: 80,
			},
			errMsg: "remote_host",
		},
		{
			name: "missing remote_port",
			params: sshExecArgs{
				Host: "1.2.3.4", Username: "user", Password: "pass",
				Action: "tunnel-local", LocalPort: 8080, RemoteHost: "target",
			},
			errMsg: "remote_port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, _ := json.Marshal(tt.params)
			result := cmd.Execute(sshTaskWith(string(params)))
			if result.Status != "error" {
				t.Errorf("expected error, got %s: %s", result.Status, result.Output)
			}
		})
	}
}

func TestSSHTunnelRemoteValidation(t *testing.T) {
	cmd := &SshExecCommand{}

	params, _ := json.Marshal(sshExecArgs{
		Host: "1.2.3.4", Username: "user", Password: "pass",
		Action: "tunnel-remote", // missing remote_port and local_port
	})
	result := cmd.Execute(sshTaskWith(string(params)))
	if result.Status != "error" {
		t.Errorf("expected error for missing remote_port, got %s", result.Status)
	}
}

func TestSSHTunnelDynamicValidation(t *testing.T) {
	cmd := &SshExecCommand{}

	params, _ := json.Marshal(sshExecArgs{
		Host: "1.2.3.4", Username: "user", Password: "pass",
		Action: "tunnel-dynamic", // missing local_port
	})
	result := cmd.Execute(sshTaskWith(string(params)))
	if result.Status != "error" {
		t.Errorf("expected error for missing local_port, got %s", result.Status)
	}
}

func TestSSHTunnelStopValidation(t *testing.T) {
	cmd := &SshExecCommand{}

	params, _ := json.Marshal(sshExecArgs{
		Action: "tunnel-stop", // missing tunnel_id
	})
	result := cmd.Execute(sshTaskWith(string(params)))
	if result.Status != "error" {
		t.Errorf("expected error for missing tunnel_id, got %s", result.Status)
	}
}

func TestSSHTunnelManagerConcurrency(t *testing.T) {
	// Verify manager is thread-safe
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = sshTunnelList()
			_ = sshTunnelStop("nonexistent")
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

// sshTaskWith creates a minimal task for testing.
func sshTaskWith(params string) structs.Task {
	return structs.Task{Params: params}
}
