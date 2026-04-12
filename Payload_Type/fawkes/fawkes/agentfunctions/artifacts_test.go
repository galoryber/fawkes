package agentfunctions

import "testing"

// --- extractChainContext Tests ---

func TestExtractChainContext_PureJSON(t *testing.T) {
	input := `{"host":"192.168.100.51","username":"admin","password":"secret"}`
	ctx := extractChainContext(input)

	if ctx["host"] != "192.168.100.51" {
		t.Errorf("host = %q, want 192.168.100.51", ctx["host"])
	}
	if ctx["username"] != "admin" {
		t.Errorf("username = %q, want admin", ctx["username"])
	}
	if ctx["password"] != "secret" {
		t.Errorf("password = %q, want secret", ctx["password"])
	}
}

func TestExtractChainContext_WithMythicAppended(t *testing.T) {
	// Mythic appends extra text after the JSON
	input := `{"host":"10.0.0.1","username":"user"}
The following arguments were supplied by the creating task but aren't being used: host`
	ctx := extractChainContext(input)

	if ctx["host"] != "10.0.0.1" {
		t.Errorf("host = %q, want 10.0.0.1", ctx["host"])
	}
	if ctx["username"] != "user" {
		t.Errorf("username = %q, want user", ctx["username"])
	}
}

func TestExtractChainContext_JSONOnSecondLine(t *testing.T) {
	input := `some random text
{"key":"value"}
more text`
	ctx := extractChainContext(input)

	if ctx["key"] != "value" {
		t.Errorf("key = %q, want value", ctx["key"])
	}
}

func TestExtractChainContext_EmptyInput(t *testing.T) {
	ctx := extractChainContext("")
	if len(ctx) != 0 {
		t.Errorf("expected empty map, got %v", ctx)
	}
}

func TestExtractChainContext_NoJSON(t *testing.T) {
	ctx := extractChainContext("this is plain text with no json")
	if len(ctx) != 0 {
		t.Errorf("expected empty map for no JSON, got %v", ctx)
	}
}

func TestExtractChainContext_EmptyJSON(t *testing.T) {
	ctx := extractChainContext("{}")
	if len(ctx) != 0 {
		t.Errorf("expected empty map for {}, got %d entries", len(ctx))
	}
}

func TestExtractChainContext_InvalidJSON(t *testing.T) {
	ctx := extractChainContext("{invalid json}")
	if len(ctx) != 0 {
		t.Errorf("expected empty map for invalid JSON, got %v", ctx)
	}
}

func TestExtractChainContext_FullChain(t *testing.T) {
	// Realistic chain context with all credential fields
	input := `{"host":"dc01.example.com","username":"admin@example.com","password":"P@ss1","domain":"example.com","hash":"","action":"spray"}`
	ctx := extractChainContext(input)

	if ctx["host"] != "dc01.example.com" {
		t.Errorf("host = %q", ctx["host"])
	}
	if ctx["domain"] != "example.com" {
		t.Errorf("domain = %q", ctx["domain"])
	}
	if ctx["hash"] != "" {
		t.Errorf("hash should be empty, got %q", ctx["hash"])
	}
}

func TestExtractChainContext_WhitespaceAroundJSON(t *testing.T) {
	input := `   {"key":"value"}   `
	ctx := extractChainContext(input)
	if ctx["key"] != "value" {
		t.Errorf("key = %q, want value", ctx["key"])
	}
}
