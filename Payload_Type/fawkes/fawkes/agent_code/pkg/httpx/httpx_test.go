package httpx

import (
	"encoding/json"
	"testing"
)

func TestParseAgentConfig(t *testing.T) {
	configJSON := `{
		"name": "test-variation",
		"get": {
			"verb": "GET",
			"uris": ["/api/v1/data", "/api/v2/info"],
			"client": {
				"headers": {"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
				"parameters": {"token": "abc123"},
				"message": {"location": "cookie", "name": "__cfduid"},
				"transforms": [
					{"action": "base64url", "value": ""}
				]
			},
			"server": {
				"headers": {"Content-Type": "text/html"},
				"transforms": [
					{"action": "xor", "value": "serverkey"},
					{"action": "base64", "value": ""}
				]
			}
		},
		"post": {
			"verb": "POST",
			"uris": ["/submit"],
			"client": {
				"headers": {"Content-Type": "application/json"},
				"message": {"location": "body"},
				"transforms": [
					{"action": "base64", "value": ""}
				]
			},
			"server": {
				"headers": {},
				"transforms": []
			}
		}
	}`

	cfg, err := ParseAgentConfig([]byte(configJSON))
	if err != nil {
		t.Fatalf("ParseAgentConfig failed: %v", err)
	}

	if cfg.Name != "test-variation" {
		t.Fatalf("name: got %q, want %q", cfg.Name, "test-variation")
	}
	if cfg.Get.Verb != "GET" {
		t.Fatalf("get verb: got %q, want GET", cfg.Get.Verb)
	}
	if len(cfg.Get.URIs) != 2 {
		t.Fatalf("get uris count: got %d, want 2", len(cfg.Get.URIs))
	}
	if cfg.Get.Client.Message.Location != "cookie" {
		t.Fatalf("get message location: got %q, want cookie", cfg.Get.Client.Message.Location)
	}
	if cfg.Get.Client.Message.Name != "__cfduid" {
		t.Fatalf("get message name: got %q, want __cfduid", cfg.Get.Client.Message.Name)
	}
	if len(cfg.Get.Client.Transforms) != 1 {
		t.Fatalf("get client transforms: got %d, want 1", len(cfg.Get.Client.Transforms))
	}
	if cfg.Get.Client.Transforms[0].Action != "base64url" {
		t.Fatalf("get client transform action: got %q, want base64url", cfg.Get.Client.Transforms[0].Action)
	}
	if len(cfg.Get.Server.Transforms) != 2 {
		t.Fatalf("get server transforms: got %d, want 2", len(cfg.Get.Server.Transforms))
	}
	if cfg.Post.Verb != "POST" {
		t.Fatalf("post verb: got %q, want POST", cfg.Post.Verb)
	}
	if cfg.Post.Client.Message.Location != "body" {
		t.Fatalf("post message location: got %q, want body", cfg.Post.Client.Message.Location)
	}
}

func TestParseAgentConfigInvalid(t *testing.T) {
	_, err := ParseAgentConfig([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseAgentConfigEmpty(t *testing.T) {
	cfg, err := ParseAgentConfig([]byte("{}"))
	if err != nil {
		t.Fatalf("ParseAgentConfig failed: %v", err)
	}
	if cfg.Name != "" {
		t.Fatalf("name should be empty: got %q", cfg.Name)
	}
}

func TestDomainSelectionFailover(t *testing.T) {
	profile := &HTTPXProfile{
		DomainRotation:    "fail-over",
		FailoverThreshold: 3,
	}

	cfg := &sensitiveConfig{
		Domains: []string{"https://primary.com", "https://backup1.com", "https://backup2.com"},
	}

	// Should start with primary
	domain := profile.selectDomain(cfg)
	if domain != "https://primary.com" {
		t.Fatalf("expected primary domain, got %q", domain)
	}

	// Simulate failures below threshold
	profile.recordFailure(cfg)
	profile.recordFailure(cfg)
	domain = profile.selectDomain(cfg)
	if domain != "https://primary.com" {
		t.Fatalf("should still be on primary after 2 failures, got %q", domain)
	}

	// Third failure triggers failover
	profile.recordFailure(cfg)
	domain = profile.selectDomain(cfg)
	if domain != "https://backup1.com" {
		t.Fatalf("should failover to backup1 after 3 failures, got %q", domain)
	}
}

func TestDomainSelectionRoundRobin(t *testing.T) {
	profile := &HTTPXProfile{
		DomainRotation: "round-robin",
	}

	cfg := &sensitiveConfig{
		Domains: []string{"https://a.com", "https://b.com", "https://c.com"},
	}

	got := make([]string, 6)
	for i := 0; i < 6; i++ {
		got[i] = profile.selectDomain(cfg)
	}

	expected := []string{
		"https://a.com", "https://b.com", "https://c.com",
		"https://a.com", "https://b.com", "https://c.com",
	}
	for i, want := range expected {
		if got[i] != want {
			t.Fatalf("round-robin[%d]: got %q, want %q", i, got[i], want)
		}
	}
}

func TestDomainSelectionRandom(t *testing.T) {
	profile := &HTTPXProfile{
		DomainRotation: "random",
	}

	cfg := &sensitiveConfig{
		Domains: []string{"https://a.com", "https://b.com"},
	}

	// Just verify it returns valid domains
	for i := 0; i < 20; i++ {
		domain := profile.selectDomain(cfg)
		if domain != "https://a.com" && domain != "https://b.com" {
			t.Fatalf("random returned invalid domain: %q", domain)
		}
	}
}

func TestDomainSelectionSingle(t *testing.T) {
	profile := &HTTPXProfile{
		DomainRotation: "fail-over",
	}

	cfg := &sensitiveConfig{
		Domains: []string{"https://only.com"},
	}

	domain := profile.selectDomain(cfg)
	if domain != "https://only.com" {
		t.Fatalf("single domain: got %q", domain)
	}
}

func TestURISelection(t *testing.T) {
	profile := &HTTPXProfile{}

	verbCfg := &VerbConfig{
		URIs: []string{"/api/v1", "/api/v2", "/data"},
	}

	got := make([]string, 6)
	for i := 0; i < 6; i++ {
		got[i] = profile.selectURI(verbCfg)
	}

	expected := []string{"/api/v1", "/api/v2", "/data", "/api/v1", "/api/v2", "/data"}
	for i, want := range expected {
		if got[i] != want {
			t.Fatalf("uri[%d]: got %q, want %q", i, got[i], want)
		}
	}
}

func TestURISelectionEmpty(t *testing.T) {
	profile := &HTTPXProfile{}
	verbCfg := &VerbConfig{URIs: nil}

	uri := profile.selectURI(verbCfg)
	if uri != "/" {
		t.Fatalf("empty URIs should return /: got %q", uri)
	}
}

func TestConfigVaultSealUnseal(t *testing.T) {
	profile := &HTTPXProfile{
		Domains:       []string{"https://test.com"},
		EncryptionKey: "dGVzdGtleQ==",
		CallbackUUID:  "test-uuid-1234",
		Config: &AgentConfig{
			Name: "test",
			Get:  VerbConfig{Verb: "GET", URIs: []string{"/get"}},
			Post: VerbConfig{Verb: "POST", URIs: []string{"/post"}},
		},
	}

	// Seal
	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	// Verify fields are zeroed
	if profile.Domains != nil {
		t.Fatal("Domains should be nil after seal")
	}
	if profile.EncryptionKey != "" {
		t.Fatal("EncryptionKey should be empty after seal")
	}
	if profile.Config != nil {
		t.Fatal("Config should be nil after seal")
	}

	// Unseal via getConfig
	cfg := profile.getConfig()
	if cfg == nil {
		t.Fatal("getConfig returned nil")
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0] != "https://test.com" {
		t.Fatalf("Domains mismatch: got %v", cfg.Domains)
	}
	if cfg.EncryptionKey != "dGVzdGtleQ==" {
		t.Fatalf("EncryptionKey mismatch: got %q", cfg.EncryptionKey)
	}
	if cfg.CallbackUUID != "test-uuid-1234" {
		t.Fatalf("CallbackUUID mismatch: got %q", cfg.CallbackUUID)
	}
	if cfg.Config.Name != "test" {
		t.Fatalf("Config name mismatch: got %q", cfg.Config.Name)
	}
}

func TestUpdateCallbackUUID(t *testing.T) {
	profile := &HTTPXProfile{
		Domains:       []string{"https://test.com"},
		EncryptionKey: "key",
		Config:        &AgentConfig{Name: "test"},
	}

	// Without vault
	profile.UpdateCallbackUUID("uuid-1")
	if profile.GetCallbackUUID() != "uuid-1" {
		t.Fatalf("UUID without vault: got %q", profile.GetCallbackUUID())
	}

	// Seal and update
	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}
	profile.UpdateCallbackUUID("uuid-2")
	if profile.GetCallbackUUID() != "uuid-2" {
		t.Fatalf("UUID with vault: got %q", profile.GetCallbackUUID())
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://example.com:443", "example.com"},
		{"http://192.168.1.1:80", "192.168.1.1"},
		{"https://cdn.example.com/path", "cdn.example.com"},
		{"invalid", ""},
	}
	for _, tt := range tests {
		got := extractHost(tt.url)
		if got != tt.want {
			t.Errorf("extractHost(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestSensitiveConfigJSON(t *testing.T) {
	cfg := &sensitiveConfig{
		Domains:       []string{"https://a.com", "https://b.com"},
		EncryptionKey: "testkey",
		CallbackUUID:  "uuid-test",
		Config: &AgentConfig{
			Name: "variation1",
			Get:  VerbConfig{Verb: "GET"},
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var restored sensitiveConfig
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(restored.Domains) != 2 {
		t.Fatalf("domains count: got %d, want 2", len(restored.Domains))
	}
	if restored.Config.Name != "variation1" {
		t.Fatalf("config name: got %q", restored.Config.Name)
	}
}

func TestRecordFailureNoOp(t *testing.T) {
	// round-robin and random modes should not trigger failover
	noopCfg := &sensitiveConfig{
		Domains: []string{"https://a.com", "https://b.com"},
	}
	profile := &HTTPXProfile{
		DomainRotation:    "round-robin",
		FailoverThreshold: 1,
	}
	profile.recordFailure(noopCfg)
	if profile.activeDomainIdx.Load() != 0 {
		t.Fatal("round-robin should not failover")
	}

	profile.DomainRotation = "random"
	profile.recordFailure(noopCfg)
	if profile.activeDomainIdx.Load() != 0 {
		t.Fatal("random should not failover")
	}
}

func TestEncryptDecryptMessage(t *testing.T) {
	profile := &HTTPXProfile{}

	// Generate a test AES key (32 bytes, base64-encoded)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	encKey := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

	msg := []byte(`{"action":"checkin","uuid":"test-uuid"}`)

	encrypted, err := profile.encryptMessage(msg, encKey)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Simulate response format: UUID prefix + encrypted data
	uuidPrefix := []byte("12345678-1234-1234-1234-123456789012")
	responseData := append(uuidPrefix, encrypted...) //nolint:gocritic // intentional: construct new slice

	decrypted, err := profile.decryptResponse(responseData, encKey)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if string(decrypted) != string(msg) {
		t.Fatalf("decrypt mismatch: got %q, want %q", decrypted, msg)
	}
}
