package commands

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// sniffTelnetTracker tracks Telnet login sequences across multiple packets.
// Telnet sends username and password as separate line-based messages.
type sniffTelnetTracker struct {
	mu      sync.Mutex
	pending map[string]string // connection key → username
}

func (tt *sniffTelnetTracker) process(payload []byte, meta *packetMeta) *sniffCredential {
	// Only check Telnet port
	if meta.DstPort != 23 && meta.SrcPort != 23 {
		return nil
	}

	// Skip Telnet negotiation bytes (IAC commands: 0xFF followed by command and option)
	cleaned := stripTelnetIAC(payload)
	s := strings.TrimSpace(string(cleaned))

	if len(s) == 0 || len(s) > 512 {
		return nil
	}

	key := fmt.Sprintf("%s:%d->%s:%d", meta.SrcIP, meta.SrcPort, meta.DstIP, meta.DstPort)

	tt.mu.Lock()
	defer tt.mu.Unlock()

	// Check if server is sending a login/password prompt
	// Prompts come FROM port 23 (server→client)
	if meta.SrcPort == 23 {
		lower := strings.ToLower(s)
		// If server sends "Password:" prompt and we have a pending username,
		// the next client packet will be the password — this is handled below.
		// If server sends "login:" prompt, that just means the client hasn't typed yet.
		_ = lower
		return nil
	}

	// Client data (toward port 23)
	// If we have a pending username for this connection, this is the password
	if username, ok := tt.pending[key]; ok {
		delete(tt.pending, key)
		// Skip if it looks like a Telnet command rather than a password
		if len(s) > 0 {
			return &sniffCredential{
				Protocol:  "telnet",
				SrcIP:     meta.SrcIP,
				SrcPort:   meta.SrcPort,
				DstIP:     meta.DstIP,
				DstPort:   meta.DstPort,
				Username:  username,
				Password:  s,
				Timestamp: time.Now().Unix(),
			}
		}
		return nil
	}

	// No pending username — this is the username (first client input)
	// Store it and wait for the password in the next client packet
	if len(s) > 0 && len(s) <= 128 && !strings.ContainsAny(s, "\x00\xff") {
		tt.pending[key] = s
	}

	return nil
}

// stripTelnetIAC removes Telnet IAC (Interpret As Command) sequences from payload.
// IAC sequences: 0xFF followed by 1 command byte, optionally followed by 1 option byte.
func stripTelnetIAC(data []byte) []byte {
	result := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if data[i] == 0xFF && i+1 < len(data) {
			cmd := data[i+1]
			if cmd == 0xFF {
				// Escaped 0xFF — literal byte
				result = append(result, 0xFF)
				i += 2
			} else if cmd >= 0xFB && cmd <= 0xFE {
				// WILL, WONT, DO, DONT — skip 3 bytes (IAC + cmd + option)
				i += 3
			} else if cmd == 0xFA {
				// Subnegotiation — skip until IAC SE (0xFF 0xF0)
				i += 2
				for i+1 < len(data) {
					if data[i] == 0xFF && data[i+1] == 0xF0 {
						i += 2
						break
					}
					i++
				}
			} else {
				// Other 2-byte IAC command
				i += 2
			}
		} else {
			result = append(result, data[i])
			i++
		}
	}
	return result
}
