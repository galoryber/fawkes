package commands

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
)

func TestSMBServerNegotiateResponse(t *testing.T) {
	var challenge [8]byte
	rand.Read(challenge[:])

	resp := smbServerBuildNegotiateResp(0, challenge, 0)

	if len(resp) < smb2HeaderSize+64 {
		t.Fatalf("negotiate response too short: %d bytes", len(resp))
	}
	if string(resp[0:4]) != smb2Magic {
		t.Error("missing SMB2 magic")
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != smb2StatusOK {
		t.Errorf("expected STATUS_OK, got 0x%08X", status)
	}
	cmd := binary.LittleEndian.Uint16(resp[12:14])
	if cmd != smb2CmdNegotiate {
		t.Errorf("expected NEGOTIATE command, got 0x%04X", cmd)
	}
	flags := binary.LittleEndian.Uint32(resp[16:20])
	if flags&smb2FlagResponse == 0 {
		t.Error("response flag not set")
	}
	payload := resp[smb2HeaderSize:]
	structSize := binary.LittleEndian.Uint16(payload[0:2])
	if structSize != 65 {
		t.Errorf("expected StructureSize 65, got %d", structSize)
	}
	dialect := binary.LittleEndian.Uint16(payload[4:6])
	if dialect != smb2DialectSMB210 {
		t.Errorf("expected SMB 2.1 dialect, got 0x%04X", dialect)
	}
	secBufLen := binary.LittleEndian.Uint16(payload[58:60])
	if secBufLen == 0 {
		t.Error("security buffer length is 0 — no SPNEGO hint")
	}
}

func TestSMBServerSessionSetupResponse(t *testing.T) {
	// Type 2 challenge
	var challenge [8]byte
	rand.Read(challenge[:])
	type2 := buildNTLMType2(challenge)
	spnego := smbServerWrapType2SPNEGO(type2)

	resp := smbServerBuildSessionSetupResp(1, 0x1234, smb2StatusMoreProcessing, spnego)

	if len(resp) < smb2HeaderSize+8 {
		t.Fatalf("session setup response too short: %d bytes", len(resp))
	}
	if string(resp[0:4]) != smb2Magic {
		t.Error("missing SMB2 magic")
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != smb2StatusMoreProcessing {
		t.Errorf("expected STATUS_MORE_PROCESSING, got 0x%08X", status)
	}
	cmd := binary.LittleEndian.Uint16(resp[12:14])
	if cmd != smb2CmdSessionSetup {
		t.Errorf("expected SESSION_SETUP, got 0x%04X", cmd)
	}
	sessionID := binary.LittleEndian.Uint64(resp[40:48])
	if sessionID != 0x1234 {
		t.Errorf("expected sessionID 0x1234, got 0x%X", sessionID)
	}
}

func TestSMBServerSessionSetupLogonFailure(t *testing.T) {
	resp := smbServerBuildSessionSetupResp(2, 0xABCD, smb2StatusLogonFailure, nil)

	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != smb2StatusLogonFailure {
		t.Errorf("expected LOGON_FAILURE, got 0x%08X", status)
	}
	payload := resp[smb2HeaderSize:]
	secBufLen := binary.LittleEndian.Uint16(payload[6:8])
	if secBufLen != 0 {
		t.Errorf("expected empty security buffer, got length %d", secBufLen)
	}
}

func TestSMBServerSPNEGOHint(t *testing.T) {
	hint := smbServerBuildNegHintSPNEGO()

	if len(hint) == 0 {
		t.Fatal("empty SPNEGO hint")
	}
	if hint[0] != 0x60 {
		t.Errorf("expected APPLICATION tag 0x60, got 0x%02X", hint[0])
	}
	if !bytes.Contains(hint, spnegoOID) {
		t.Error("SPNEGO hint missing SPNEGO OID")
	}
	if !bytes.Contains(hint, ntlmsspOID) {
		t.Error("SPNEGO hint missing NTLMSSP OID")
	}
}

func TestSMBServerType2SPNEGOWrap(t *testing.T) {
	var challenge [8]byte
	rand.Read(challenge[:])
	type2 := buildNTLMType2(challenge)

	wrapped := smbServerWrapType2SPNEGO(type2)

	if len(wrapped) == 0 {
		t.Fatal("empty SPNEGO wrapped Type 2")
	}
	if wrapped[0] != 0xa1 {
		t.Errorf("expected context tag [1] (0xa1), got 0x%02X", wrapped[0])
	}
	extracted := spnegoExtractNTLMToken(wrapped)
	if extracted == nil {
		t.Fatal("cannot extract NTLM from SPNEGO-wrapped Type 2")
	}
	if !bytes.Equal(extracted[0:8], sniffNTLMSig) {
		t.Error("extracted message missing NTLMSSP signature")
	}
	msgType := binary.LittleEndian.Uint32(extracted[8:12])
	if msgType != ntlmTypeChallenge {
		t.Errorf("expected Type 2, got type %d", msgType)
	}
	if !bytes.Equal(extracted[24:32], challenge[:]) {
		t.Error("challenge mismatch in extracted Type 2")
	}
}

func TestSMBServerHashExtractionFromType3(t *testing.T) {
	challenge := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Build a synthetic NTLM Type 3 message with NTLMv2 response
	type3 := buildTestType3("TESTUSER", "TESTDOMAIN", challenge)
	if type3 == nil {
		t.Skip("could not build test Type 3")
	}

	hash := extractNTLMv2Hash(type3, challenge)
	if hash == nil {
		t.Fatal("failed to extract hash from Type 3")
	}
	if hash.Username != "TESTUSER" {
		t.Errorf("expected username TESTUSER, got %s", hash.Username)
	}
	if hash.Domain != "TESTDOMAIN" {
		t.Errorf("expected domain TESTDOMAIN, got %s", hash.Domain)
	}
	if hash.ServerChallenge != hex.EncodeToString(challenge[:]) {
		t.Errorf("wrong server challenge in hash")
	}
	if hash.HashcatFormat == "" {
		t.Error("empty hashcat format")
	}
	// Verify hashcat format: user::domain:challenge:ntproofstr:blob
	parts := bytes.Count([]byte(hash.HashcatFormat), []byte(":"))
	if parts < 5 {
		t.Errorf("hashcat format should have 5+ colons, got %d: %s", parts, hash.HashcatFormat)
	}
}

func TestSMBServerGenSessionID(t *testing.T) {
	ids := make(map[uint64]bool)
	for i := 0; i < 100; i++ {
		id := smbServerGenSessionID()
		if id == 0 {
			continue
		}
		if ids[id] {
			t.Errorf("duplicate session ID: %d", id)
		}
		ids[id] = true
	}
}

func TestSMBServerReadWriteRoundtrip(t *testing.T) {
	// Simulate NetBIOS-framed packet read/write via pipe
	client, server := createTestPipe(t)
	defer client.Close()
	defer server.Close()

	testData := []byte("\xFESMB" + "test payload data")
	go func() {
		smbServerWritePacket(client, testData)
	}()

	pkt, err := smbServerReadPacket(server)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !bytes.Equal(pkt, testData) {
		t.Errorf("roundtrip mismatch: got %d bytes, want %d", len(pkt), len(testData))
	}
}

// buildTestType3 constructs a minimal NTLM Type 3 message for testing.
func buildTestType3(username, domain string, challenge [8]byte) []byte {
	userUTF16 := smbTestEncodeUTF16LE(username)
	domainUTF16 := smbTestEncodeUTF16LE(domain)

	// NtChallengeResponse: 16 bytes NTProofStr + 28 bytes minimal blob
	ntResp := make([]byte, 44)
	rand.Read(ntResp[:16]) // NTProofStr
	// Minimal client blob: RespType=1, HiRespType=1, Reserved, TimeStamp, ChallengeFromClient, Reserved2
	ntResp[16] = 0x01 // RespType
	ntResp[17] = 0x01 // HiRespType
	rand.Read(ntResp[28:36]) // ChallengeFromClient

	// Build Type 3 with security buffers
	// Fixed header: 88 bytes (up to flags at offset 60)
	headerSize := 88
	dataStart := headerSize

	type3 := make([]byte, headerSize+len(domainUTF16)+len(userUTF16)+len(ntResp))
	copy(type3[0:8], sniffNTLMSig)
	binary.LittleEndian.PutUint32(type3[8:12], 3) // Type 3

	// LmChallengeResponse (offset 12): empty
	binary.LittleEndian.PutUint16(type3[12:14], 0)
	binary.LittleEndian.PutUint16(type3[14:16], 0)
	binary.LittleEndian.PutUint32(type3[16:20], uint32(dataStart))

	// NtChallengeResponse (offset 20)
	ntRespOff := dataStart + len(domainUTF16) + len(userUTF16)
	binary.LittleEndian.PutUint16(type3[20:22], uint16(len(ntResp)))
	binary.LittleEndian.PutUint16(type3[22:24], uint16(len(ntResp)))
	binary.LittleEndian.PutUint32(type3[24:28], uint32(ntRespOff))

	// DomainName (offset 28)
	domainOff := dataStart
	binary.LittleEndian.PutUint16(type3[28:30], uint16(len(domainUTF16)))
	binary.LittleEndian.PutUint16(type3[30:32], uint16(len(domainUTF16)))
	binary.LittleEndian.PutUint32(type3[32:36], uint32(domainOff))

	// UserName (offset 36)
	userOff := dataStart + len(domainUTF16)
	binary.LittleEndian.PutUint16(type3[36:38], uint16(len(userUTF16)))
	binary.LittleEndian.PutUint16(type3[38:40], uint16(len(userUTF16)))
	binary.LittleEndian.PutUint32(type3[40:44], uint32(userOff))

	// Workstation (offset 44): empty
	binary.LittleEndian.PutUint16(type3[44:46], 0)
	binary.LittleEndian.PutUint16(type3[46:48], 0)
	binary.LittleEndian.PutUint32(type3[48:52], uint32(dataStart))

	// Negotiate Flags (offset 60): UNICODE
	binary.LittleEndian.PutUint32(type3[60:64], 0x01) // NEGOTIATE_UNICODE

	// Copy data
	copy(type3[domainOff:], domainUTF16)
	copy(type3[userOff:], userUTF16)
	copy(type3[ntRespOff:], ntResp)

	return type3
}

func smbTestEncodeUTF16LE(s string) []byte {
	out := make([]byte, len(s)*2)
	for i, c := range s {
		out[i*2] = byte(c)
		out[i*2+1] = byte(c >> 8)
	}
	return out
}

func createTestPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ch <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server := <-ch
	return client, server
}
