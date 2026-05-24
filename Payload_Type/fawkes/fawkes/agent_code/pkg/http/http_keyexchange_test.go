package http

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestDeriveKey_Deterministic(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	salt := make([]byte, 32)
	rand.Read(salt)

	key1, err := deriveKey(secret, salt)
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	key2, err := deriveKey(secret, salt)
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
	for i := range key1 {
		if key1[i] != key2[i] {
			t.Fatal("same inputs should produce same key")
		}
	}
}

func TestDeriveKey_DifferentSecrets(t *testing.T) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	rand.Read(secret1)
	rand.Read(secret2)
	salt := make([]byte, 32)

	key1, _ := deriveKey(secret1, salt)
	key2, _ := deriveKey(secret2, salt)

	same := true
	for i := range key1 {
		if key1[i] != key2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different secrets should produce different keys")
	}
}

func TestDeriveKey_DifferentSalts(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	salt1 := make([]byte, 32)
	salt2 := make([]byte, 32)
	rand.Read(salt1)
	rand.Read(salt2)

	key1, _ := deriveKey(secret, salt1)
	key2, _ := deriveKey(secret, salt2)

	same := true
	for i := range key1 {
		if key1[i] != key2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different salts should produce different keys")
	}
}

func TestKeyRotationState_ShouldInitiate(t *testing.T) {
	kr := newKeyRotationState(3)
	if kr.ShouldInitiateExchange() {
		t.Error("should not initiate on first check-in")
	}
	if kr.ShouldInitiateExchange() {
		t.Error("should not initiate on second check-in")
	}
	if !kr.ShouldInitiateExchange() {
		t.Error("should initiate on third check-in (interval=3)")
	}
}

func TestKeyRotationState_DisabledWhenZero(t *testing.T) {
	kr := newKeyRotationState(0)
	for i := 0; i < 100; i++ {
		if kr.ShouldInitiateExchange() {
			t.Fatal("should never initiate when interval=0")
		}
	}
}

func TestKeyRotationState_NoDoubleInitiate(t *testing.T) {
	kr := newKeyRotationState(1)
	if !kr.ShouldInitiateExchange() {
		t.Fatal("first check should trigger")
	}
	_, _ = kr.GenerateEphemeralKey()
	kr.mu.Lock()
	kr.phase = phaseExchanged
	kr.mu.Unlock()

	if kr.ShouldInitiateExchange() {
		t.Error("should not initiate while exchange is in progress")
	}
}

func TestGenerateEphemeralKey_ValidBase64(t *testing.T) {
	kr := newKeyRotationState(100)
	pub, err := kr.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("GenerateEphemeralKey: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("invalid base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("X25519 public key length = %d, want 32", len(decoded))
	}
}

func TestGenerateEphemeralKey_Unique(t *testing.T) {
	kr := newKeyRotationState(100)
	pub1, _ := kr.GenerateEphemeralKey()
	pub2, _ := kr.GenerateEphemeralKey()
	if pub1 == pub2 {
		t.Error("consecutive keys should be unique")
	}
}

func TestProcessServerKey_FullExchange(t *testing.T) {
	agentKR := newKeyRotationState(100)
	currentKey := make([]byte, 32)
	rand.Read(currentKey)

	agentPub, err := agentKR.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("agent keygen: %v", err)
	}

	curve := ecdh.X25519()
	serverPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}
	serverPub := base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes())

	agentPubBytes, _ := base64.StdEncoding.DecodeString(agentPub)
	agentPubKey, _ := curve.NewPublicKey(agentPubBytes)
	serverShared, err := serverPriv.ECDH(agentPubKey)
	if err != nil {
		t.Fatalf("server ECDH: %v", err)
	}
	serverDerivedKey, err := deriveKey(serverShared, currentKey)
	if err != nil {
		t.Fatalf("server deriveKey: %v", err)
	}

	agentDerivedKey, err := agentKR.ProcessServerKey(serverPub, currentKey)
	if err != nil {
		t.Fatalf("agent ProcessServerKey: %v", err)
	}

	if len(agentDerivedKey) != 32 {
		t.Errorf("derived key length = %d, want 32", len(agentDerivedKey))
	}

	for i := range agentDerivedKey {
		if agentDerivedKey[i] != serverDerivedKey[i] {
			t.Fatal("agent and server derived different keys")
		}
	}

	if agentKR.Phase() != phaseExchanged {
		t.Errorf("phase = %d, want phaseExchanged", agentKR.Phase())
	}
}

func TestProcessServerKey_NoPrivateKey(t *testing.T) {
	kr := newKeyRotationState(100)
	_, err := kr.ProcessServerKey("AAAA", []byte("key"))
	if err == nil {
		t.Error("should fail without ephemeral key")
	}
}

func TestProcessServerKey_InvalidBase64(t *testing.T) {
	kr := newKeyRotationState(100)
	kr.GenerateEphemeralKey()
	_, err := kr.ProcessServerKey("not-valid-base64!!!", []byte("key"))
	if err == nil {
		t.Error("should fail with invalid base64")
	}
}

func TestProcessServerKey_InvalidKeyLength(t *testing.T) {
	kr := newKeyRotationState(100)
	kr.GenerateEphemeralKey()
	shortKey := base64.StdEncoding.EncodeToString([]byte("too-short"))
	_, err := kr.ProcessServerKey(shortKey, []byte("key"))
	if err == nil {
		t.Error("should fail with wrong-length public key")
	}
}

func TestConfirmRotation_ResetsState(t *testing.T) {
	kr := newKeyRotationState(1)
	kr.ShouldInitiateExchange()
	kr.GenerateEphemeralKey()

	curve := ecdh.X25519()
	serverPriv, _ := curve.GenerateKey(rand.Reader)
	serverPub := base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes())
	kr.ProcessServerKey(serverPub, make([]byte, 32))

	if kr.Phase() != phaseExchanged {
		t.Fatal("should be in exchanged phase")
	}

	kr.ConfirmRotation()

	if kr.Phase() != phaseIdle {
		t.Errorf("phase after confirm = %d, want phaseIdle", kr.Phase())
	}

	if !kr.ShouldInitiateExchange() {
		t.Error("should be able to initiate new exchange after confirm")
	}
}

func TestAbort_ResetsState(t *testing.T) {
	kr := newKeyRotationState(1)
	kr.ShouldInitiateExchange()
	kr.GenerateEphemeralKey()

	if kr.Phase() != phaseIdle {
		// Phase is still idle until ProcessServerKey
	}

	kr.Abort()

	if kr.Phase() != phaseIdle {
		t.Errorf("phase after abort = %d, want phaseIdle", kr.Phase())
	}
}

func TestRotateEncryptionKey_UnsealedProfile(t *testing.T) {
	profile := &HTTPProfile{
		EncryptionKey: "oldkey123",
	}

	err := profile.RotateEncryptionKey("newkey456")
	if err != nil {
		t.Fatalf("RotateEncryptionKey: %v", err)
	}
	if profile.EncryptionKey != "newkey456" {
		t.Errorf("key = %s, want newkey456", profile.EncryptionKey)
	}
}

func TestRotateEncryptionKey_SealedProfile(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:       "http://test.com",
		EncryptionKey: "oldkey123",
		UserAgent:     "TestAgent",
		GetEndpoint:   "/get",
		PostEndpoint:  "/post",
	}

	err := profile.SealConfig()
	if err != nil {
		t.Fatalf("SealConfig: %v", err)
	}

	err = profile.RotateEncryptionKey("newkey789")
	if err != nil {
		t.Fatalf("RotateEncryptionKey: %v", err)
	}

	cfg := profile.getConfig()
	if cfg == nil {
		t.Fatal("getConfig returned nil after rotation")
	}
	if cfg.EncryptionKey != "newkey789" {
		t.Errorf("key = %s, want newkey789", cfg.EncryptionKey)
	}
	if cfg.BaseURL != "http://test.com" {
		t.Error("rotation should not affect other config fields")
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	zeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("b[%d] = %d, want 0", i, v)
		}
	}
}

func TestNewKeyRotationState_Defaults(t *testing.T) {
	kr := newKeyRotationState(50)
	if kr.interval != 50 {
		t.Errorf("interval = %d, want 50", kr.interval)
	}
	if kr.Phase() != phaseIdle {
		t.Errorf("initial phase = %d, want phaseIdle", kr.Phase())
	}
	if kr.checkIns != 0 {
		t.Errorf("initial checkIns = %d, want 0", kr.checkIns)
	}
}

func TestFullKeyExchange_BothSidesDeriveSameKey(t *testing.T) {
	for i := 0; i < 10; i++ {
		currentKey := make([]byte, 32)
		rand.Read(currentKey)

		agentKR := newKeyRotationState(1)
		agentKR.ShouldInitiateExchange()
		agentPub, _ := agentKR.GenerateEphemeralKey()

		curve := ecdh.X25519()
		serverPriv, _ := curve.GenerateKey(rand.Reader)
		serverPub := base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes())

		agentPubBytes, _ := base64.StdEncoding.DecodeString(agentPub)
		agentPubKey, _ := curve.NewPublicKey(agentPubBytes)
		serverShared, _ := serverPriv.ECDH(agentPubKey)
		serverKey, _ := deriveKey(serverShared, currentKey)

		agentKey, err := agentKR.ProcessServerKey(serverPub, currentKey)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}

		for j := range agentKey {
			if agentKey[j] != serverKey[j] {
				t.Fatalf("iteration %d: keys differ at byte %d", i, j)
			}
		}

		agentKR.ConfirmRotation()
	}
}

func TestProcessKeyExchangeResponse_Phase1(t *testing.T) {
	currentKeyB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	profile := &HTTPProfile{
		EncryptionKey: currentKeyB64,
		keyRotation:   newKeyRotationState(1),
	}
	profile.keyRotation.ShouldInitiateExchange()
	profile.keyRotation.GenerateEphemeralKey()

	curve := ecdh.X25519()
	serverPriv, _ := curve.GenerateKey(rand.Reader)
	serverPubB64 := base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes())

	cfg := &sensitiveConfig{EncryptionKey: currentKeyB64}
	resp := map[string]interface{}{
		"key_exchange_response": serverPubB64,
	}

	profile.processKeyExchangeResponse(resp, cfg)

	if profile.keyRotation.Phase() != phaseExchanged {
		t.Errorf("phase = %d, want phaseExchanged", profile.keyRotation.Phase())
	}
	profile.keyRotation.mu.Lock()
	hasPending := profile.keyRotation.pendingKey != nil
	profile.keyRotation.mu.Unlock()
	if !hasPending {
		t.Error("expected pending key after Phase 1")
	}
}

func TestProcessKeyExchangeResponse_Phase2_RotatesKey(t *testing.T) {
	currentKey := make([]byte, 32)
	rand.Read(currentKey)
	currentKeyB64 := base64.StdEncoding.EncodeToString(currentKey)

	profile := &HTTPProfile{
		EncryptionKey: currentKeyB64,
		keyRotation:   newKeyRotationState(1),
	}
	profile.keyRotation.ShouldInitiateExchange()
	profile.keyRotation.GenerateEphemeralKey()

	curve := ecdh.X25519()
	serverPriv, _ := curve.GenerateKey(rand.Reader)
	serverPubB64 := base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes())

	cfg := &sensitiveConfig{EncryptionKey: currentKeyB64}
	profile.processKeyExchangeResponse(map[string]interface{}{
		"key_exchange_response": serverPubB64,
	}, cfg)

	if profile.keyRotation.Phase() != phaseExchanged {
		t.Fatalf("expected phaseExchanged after Phase 1")
	}

	profile.processKeyExchangeResponse(map[string]interface{}{
		"key_exchange_confirmed": true,
	}, cfg)

	if profile.keyRotation.Phase() != phaseIdle {
		t.Errorf("phase after confirmation = %d, want phaseIdle", profile.keyRotation.Phase())
	}
	if profile.EncryptionKey == currentKeyB64 {
		t.Error("encryption key should have changed after rotation")
	}
}

func TestProcessKeyExchangeResponse_NilKeyRotation(t *testing.T) {
	profile := &HTTPProfile{}
	cfg := &sensitiveConfig{EncryptionKey: "test"}
	profile.processKeyExchangeResponse(map[string]interface{}{
		"key_exchange_response": "something",
	}, cfg)
}

func TestProcessKeyExchangeResponse_InvalidServerKey_Aborts(t *testing.T) {
	currentKeyB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	profile := &HTTPProfile{
		EncryptionKey: currentKeyB64,
		keyRotation:   newKeyRotationState(1),
	}
	profile.keyRotation.ShouldInitiateExchange()
	profile.keyRotation.GenerateEphemeralKey()

	cfg := &sensitiveConfig{EncryptionKey: currentKeyB64}
	resp := map[string]interface{}{
		"key_exchange_response": "not-valid-base64!!!",
	}
	profile.processKeyExchangeResponse(resp, cfg)

	if profile.keyRotation.Phase() != phaseIdle {
		t.Errorf("phase after invalid key = %d, want phaseIdle (aborted)", profile.keyRotation.Phase())
	}
}

func TestProcessKeyExchangeResponse_ConfirmWithoutExchange_NoOp(t *testing.T) {
	currentKeyB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	profile := &HTTPProfile{
		EncryptionKey: currentKeyB64,
		keyRotation:   newKeyRotationState(1),
	}

	cfg := &sensitiveConfig{EncryptionKey: currentKeyB64}
	profile.processKeyExchangeResponse(map[string]interface{}{
		"key_exchange_confirmed": true,
	}, cfg)

	if profile.EncryptionKey != currentKeyB64 {
		t.Error("key should not change without prior exchange")
	}
}

func TestProcessKeyExchangeResponse_Phase2_WithVault(t *testing.T) {
	currentKey := make([]byte, 32)
	rand.Read(currentKey)
	currentKeyB64 := base64.StdEncoding.EncodeToString(currentKey)

	profile := &HTTPProfile{
		BaseURL:       "http://test.com",
		EncryptionKey: currentKeyB64,
		UserAgent:     "TestAgent",
		GetEndpoint:   "/get",
		PostEndpoint:  "/post",
		keyRotation:   newKeyRotationState(1),
	}
	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig: %v", err)
	}

	profile.keyRotation.ShouldInitiateExchange()
	profile.keyRotation.GenerateEphemeralKey()

	curve := ecdh.X25519()
	serverPriv, _ := curve.GenerateKey(rand.Reader)
	serverPubB64 := base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes())

	cfg := profile.getConfig()
	profile.processKeyExchangeResponse(map[string]interface{}{
		"key_exchange_response": serverPubB64,
	}, cfg)

	cfg = profile.getConfig()
	profile.processKeyExchangeResponse(map[string]interface{}{
		"key_exchange_confirmed": true,
	}, cfg)

	if profile.keyRotation.Phase() != phaseIdle {
		t.Errorf("phase = %d, want phaseIdle", profile.keyRotation.Phase())
	}

	newCfg := profile.getConfig()
	if newCfg == nil {
		t.Fatal("getConfig returned nil after vault rotation")
	}
	if newCfg.EncryptionKey == currentKeyB64 {
		t.Error("vault key should have changed after rotation")
	}
	if newCfg.BaseURL != "http://test.com" {
		t.Error("rotation should not affect other vault fields")
	}
}

func TestKeyRotationState_IntegrationWithProfile(t *testing.T) {
	profile := &HTTPProfile{
		keyRotation: newKeyRotationState(0),
	}
	if profile.keyRotation.ShouldInitiateExchange() {
		t.Error("disabled rotation should never trigger")
	}

	profile2 := &HTTPProfile{
		keyRotation: newKeyRotationState(2),
	}
	if profile2.keyRotation.ShouldInitiateExchange() {
		t.Error("should not trigger on first check-in")
	}
	if !profile2.keyRotation.ShouldInitiateExchange() {
		t.Error("should trigger on second check-in (interval=2)")
	}
}
