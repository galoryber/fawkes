package commands

import (
	"testing"
)

func TestRpcCredential_PasswordAuth(t *testing.T) {
	cred, err := rpcCredential("admin", "DOMAIN", "P@ssw0rd", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
}

func TestRpcCredential_HashAuth(t *testing.T) {
	cred, err := rpcCredential("admin", "DOMAIN", "", "8846f7eaee8fb117ad06bdd830b7586c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
}

func TestRpcCredential_LMNTHashAuth(t *testing.T) {
	cred, err := rpcCredential("admin", "CORP", "", "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
}

func TestRpcCredential_NoDomain(t *testing.T) {
	cred, err := rpcCredential("localuser", "", "password123", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
}

func TestRpcCredential_NoPasswordOrHash(t *testing.T) {
	_, err := rpcCredential("admin", "DOMAIN", "", "")
	if err == nil {
		t.Error("expected error when both password and hash are empty")
	}
}

func TestRpcCredential_HashTakesPrecedence(t *testing.T) {
	// When both password and hash are provided, hash should be used (no error)
	cred, err := rpcCredential("admin", "DOMAIN", "password", "8846f7eaee8fb117ad06bdd830b7586c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
}
