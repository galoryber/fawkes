package commands

import (
	"net"
	"testing"
)

// TestBuildLLMNRResponseEdgeCases covers malformed query error paths.
func TestBuildLLMNRResponseEdgeCases(t *testing.T) {
	t.Run("malformed name (label runs past end)", func(t *testing.T) {
		// Header (12 bytes) + labelLen=20 but only 3 bytes follow — no null terminator found
		pkt := make([]byte, 12+4)
		pkt[12] = 20  // label length claims 20 bytes
		pkt[13] = 'A' // only 3 bytes actually there
		pkt[14] = 'B'
		pkt[15] = 'C'
		// Loop: nameEnd = 12, labelLen=20, nameEnd = 12+21 = 33 >= len(16) → error
		_, err := buildLLMNRResponse(pkt, net.ParseIP("10.0.0.1"))
		if err == nil {
			t.Error("expected error for malformed name (label extends past end)")
		}
	})

	t.Run("QTYPE/QCLASS truncated after valid name", func(t *testing.T) {
		// Build a valid name "AB" followed by null, then only 2 bytes (not 4)
		pkt := make([]byte, 12)                    // header
		pkt = append(pkt, 2, 'A', 'B', 0)         // name: len=2, "AB", null
		pkt = append(pkt, 0x00, 0x01)              // only QTYPE, QCLASS missing
		// nameEnd = 12+1+2+1 = 16, nameEnd+4 = 20 > len(pkt) = 18 → error
		_, err := buildLLMNRResponse(pkt, net.ParseIP("10.0.0.1"))
		if err == nil {
			t.Error("expected error when QTYPE/QCLASS truncated")
		}
	})
}

// TestBuildNBTNSResponseEdgeCases covers malformed query error paths.
func TestBuildNBTNSResponseEdgeCases(t *testing.T) {
	t.Run("too short (< 12 bytes)", func(t *testing.T) {
		_, err := buildNBTNSResponse([]byte{0x00, 0x01}, net.ParseIP("10.0.0.1"))
		if err == nil {
			t.Error("expected error for short NBT-NS packet")
		}
	})

	t.Run("malformed name (label runs past end)", func(t *testing.T) {
		pkt := make([]byte, 12+4)
		pkt[12] = 20  // label length claims 20 bytes
		pkt[13] = 'A' // only 3 bytes follow
		pkt[14] = 'B'
		pkt[15] = 'C'
		_, err := buildNBTNSResponse(pkt, net.ParseIP("192.168.1.1"))
		if err == nil {
			t.Error("expected error for malformed NBT-NS name")
		}
	})

	t.Run("QTYPE/QCLASS truncated after valid name", func(t *testing.T) {
		pkt := make([]byte, 12)
		pkt = append(pkt, 2, 'A', 'B', 0) // name
		pkt = append(pkt, 0x00, 0x20)     // only QTYPE
		_, err := buildNBTNSResponse(pkt, net.ParseIP("192.168.1.1"))
		if err == nil {
			t.Error("expected error when NBT-NS QTYPE/QCLASS truncated")
		}
	})

	t.Run("IPv6 address not supported", func(t *testing.T) {
		query := buildTestNBTNSQuery("WPAD")
		_, err := buildNBTNSResponse(query, net.ParseIP("::1"))
		if err == nil {
			t.Error("expected error for IPv6 address in NBT-NS response")
		}
	})
}

// TestExtractLLMNRQueryNameEdgeCases covers the label-overrun path.
func TestExtractLLMNRQueryNameEdgeCases(t *testing.T) {
	t.Run("label extends past end of packet", func(t *testing.T) {
		// Header (12 bytes) + labelLen=20 but only 3 content bytes
		pkt := make([]byte, 12)
		pkt = append(pkt, 20, 'X', 'Y', 'Z') // label claims 20 but only 3 bytes
		name := extractLLMNRQueryName(pkt)
		if name != "" {
			t.Errorf("got %q, want empty for truncated label", name)
		}
	})

	t.Run("too short (< 13 bytes)", func(t *testing.T) {
		name := extractLLMNRQueryName(make([]byte, 10))
		if name != "" {
			t.Errorf("got %q, want empty for short packet", name)
		}
	})
}

// TestExtractNBTNSQueryNameEdgeCases covers the non-NetBIOS label path.
func TestExtractNBTNSQueryNameEdgeCases(t *testing.T) {
	t.Run("label length not 32 (not NetBIOS encoded)", func(t *testing.T) {
		// Packet with labelLen = 10 at offset 12, not 32
		pkt := make([]byte, 50)
		pkt[12] = 10 // not 32 → not a valid NetBIOS name
		name := extractNBTNSQueryName(pkt)
		if name != "" {
			t.Errorf("got %q, want empty for non-NetBIOS label length", name)
		}
	})

	t.Run("too short (< 46 bytes)", func(t *testing.T) {
		name := extractNBTNSQueryName(make([]byte, 30))
		if name != "" {
			t.Errorf("got %q, want empty for short packet", name)
		}
	})
}
