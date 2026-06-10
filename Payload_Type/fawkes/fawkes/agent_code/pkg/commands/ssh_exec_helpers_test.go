package commands

import (
	"strings"
	"testing"
)

func TestValidateSSHActionParams_ExecRequiresCommand(t *testing.T) {
	err := validateSSHActionParams("exec", sshExecArgs{})
	if err == nil {
		t.Fatal("expected error for exec without command")
	}
	if !strings.Contains(err.Error(), "command is required") {
		t.Errorf("unexpected error: %v", err)
	}

	err = validateSSHActionParams("exec", sshExecArgs{Command: "whoami"})
	if err != nil {
		t.Errorf("unexpected error with valid exec: %v", err)
	}
}

func TestValidateSSHActionParams_PushRequiresSourceAndDest(t *testing.T) {
	err := validateSSHActionParams("push", sshExecArgs{})
	if err == nil {
		t.Fatal("expected error for push without source/dest")
	}

	err = validateSSHActionParams("push", sshExecArgs{Source: "/tmp/file"})
	if err == nil {
		t.Fatal("expected error for push without destination")
	}

	err = validateSSHActionParams("push", sshExecArgs{Source: "/tmp/file", Destination: "/remote/path"})
	if err != nil {
		t.Errorf("unexpected error with valid push: %v", err)
	}
}

func TestValidateSSHActionParams_TunnelLocal(t *testing.T) {
	err := validateSSHActionParams("tunnel-local", sshExecArgs{})
	if err == nil {
		t.Fatal("expected error for tunnel-local without params")
	}

	err = validateSSHActionParams("tunnel-local", sshExecArgs{
		LocalPort: 8080, RemoteHost: "db.local", RemotePort: 3306,
	})
	if err != nil {
		t.Errorf("unexpected error with valid tunnel-local: %v", err)
	}

	err = validateSSHActionParams("tunnel-local", sshExecArgs{LocalPort: 8080})
	if err == nil {
		t.Fatal("expected error without remote_host")
	}
}

func TestValidateSSHActionParams_TunnelRemote(t *testing.T) {
	err := validateSSHActionParams("tunnel-remote", sshExecArgs{})
	if err == nil {
		t.Fatal("expected error without params")
	}

	err = validateSSHActionParams("tunnel-remote", sshExecArgs{RemotePort: 8080, LocalPort: 3000})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSSHActionParams_TunnelDynamic(t *testing.T) {
	err := validateSSHActionParams("tunnel-dynamic", sshExecArgs{})
	if err == nil {
		t.Fatal("expected error without local_port")
	}

	err = validateSSHActionParams("tunnel-dynamic", sshExecArgs{LocalPort: 1080})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSSHActionParams_CheckNoParamsNeeded(t *testing.T) {
	err := validateSSHActionParams("check", sshExecArgs{})
	if err != nil {
		t.Errorf("check should not require params: %v", err)
	}
}

func TestValidateSSHActionParams_UnknownAction(t *testing.T) {
	err := validateSSHActionParams("invalid", sshExecArgs{})
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
	if !strings.Contains(err.Error(), "unknown action") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBuildSSHAuthMethods_NoCredentials(t *testing.T) {
	methods, err := buildSSHAuthMethods(sshExecArgs{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 0 {
		t.Errorf("expected 0 methods with no creds, got %d", len(methods))
	}
}

func TestBuildSSHAuthMethods_PasswordOnly(t *testing.T) {
	methods, err := buildSSHAuthMethods(sshExecArgs{Password: "secret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 methods (password + keyboard-interactive), got %d", len(methods))
	}
}

func TestBuildSSHAuthMethods_BadKeyData(t *testing.T) {
	_, err := buildSSHAuthMethods(sshExecArgs{KeyData: "not a PEM key"})
	if err == nil {
		t.Fatal("expected error for invalid key data")
	}
}

func TestBuildSSHAuthMethods_BadKeyPath(t *testing.T) {
	_, err := buildSSHAuthMethods(sshExecArgs{KeyPath: "/nonexistent/key"})
	if err == nil {
		t.Fatal("expected error for nonexistent key path")
	}
}
