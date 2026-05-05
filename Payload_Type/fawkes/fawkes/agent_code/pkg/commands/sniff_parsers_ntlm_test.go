package commands

import (
	"encoding/binary"
	"testing"
)

// TestSniffExtractNTLMExtraErrors covers uncovered error paths in sniffExtractNTLM.
func TestSniffExtractNTLMExtraErrors(t *testing.T) {
	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49000, DstPort: 445}

	t.Run("NTLM signature found but data too short (line 118)", func(t *testing.T) {
		// Payload contains the NTLM signature but total length < 72 bytes
		payload := make([]byte, 20)
		copy(payload[0:8], sniffNTLMSig) // "NTLMSSP\x00"
		cred := sniffExtractNTLM(payload, meta)
		if cred != nil {
			t.Error("expected nil for NTLM payload shorter than 72 bytes")
		}
	})

	t.Run("NTLM type 3 with empty user field (lines 134 and 144)", func(t *testing.T) {
		// Build a minimal 72-byte NTLM type 3 message with user fLen=0.
		// readField returns "" when fLen==0 (hits line 134-136).
		// user=="" then hits line 144-146 and returns nil.
		msg := make([]byte, 72)
		copy(msg[0:8], sniffNTLMSig)
		binary.LittleEndian.PutUint32(msg[8:12], 3)  // message type = 3 (Authenticate)
		binary.LittleEndian.PutUint16(msg[36:38], 0) // user fLen = 0
		binary.LittleEndian.PutUint32(msg[40:44], 72) // user fOff points past buffer
		cred := sniffExtractNTLM(msg, meta)
		if cred != nil {
			t.Error("expected nil for NTLM type 3 with empty user field")
		}
	})
}
