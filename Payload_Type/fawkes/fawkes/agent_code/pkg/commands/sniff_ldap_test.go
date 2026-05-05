package commands

import (
	"bytes"
	"testing"
)

// TestDerSkipTLEdgeCases covers long-form encoding and error paths.
func TestDerSkipTLEdgeCases(t *testing.T) {
	t.Run("too short (< 2 bytes)", func(t *testing.T) {
		_, ok := derSkipTL([]byte{0x30})
		if ok {
			t.Error("expected false for 1-byte input")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, ok := derSkipTL([]byte{})
		if ok {
			t.Error("expected false for empty input")
		}
	})

	t.Run("long form 1 byte (0x81)", func(t *testing.T) {
		// tag=0x30, 0x81, 0x05 = 5 content bytes
		payload := make([]byte, 3+5)
		payload[0] = 0x30
		payload[1] = 0x81
		payload[2] = 5
		for i := 3; i < 8; i++ {
			payload[i] = byte(i)
		}
		rest, ok := derSkipTL(payload)
		if !ok {
			t.Fatal("expected success for long-form 1-byte length")
		}
		// derSkipTL returns data starting after the header (tag+length bytes)
		if !bytes.Equal(rest, payload[3:]) {
			t.Errorf("rest mismatch: got %v, want %v", rest, payload[3:])
		}
	})

	t.Run("long form 2 bytes (0x82)", func(t *testing.T) {
		// 0x30 0x82 0x01 0x00 = 256 content bytes
		content := make([]byte, 256)
		payload := append([]byte{0x30, 0x82, 0x01, 0x00}, content...)
		rest, ok := derSkipTL(payload)
		if !ok {
			t.Fatal("expected success for long-form 2-byte length")
		}
		if !bytes.Equal(rest, content) {
			t.Error("rest should be the content bytes")
		}
	})

	t.Run("numBytes zero (0x80 = indefinite form)", func(t *testing.T) {
		// 0x80 as length byte means numBytes=0 → invalid
		_, ok := derSkipTL([]byte{0x30, 0x80, 0x01, 0x02})
		if ok {
			t.Error("expected false for indefinite-length form (0x80)")
		}
	})

	t.Run("numBytes too large (> 4)", func(t *testing.T) {
		_, ok := derSkipTL([]byte{0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05})
		if ok {
			t.Error("expected false for numBytes > 4")
		}
	})

	t.Run("truncated long form (2+numBytes > len)", func(t *testing.T) {
		// 0x82 means 2 length bytes follow, but only 1 is present
		_, ok := derSkipTL([]byte{0x30, 0x82, 0x01})
		if ok {
			t.Error("expected false for truncated long-form length")
		}
	})

	t.Run("start beyond buffer", func(t *testing.T) {
		// Short form: tag=0x30, length=10, but no content bytes after header
		// derSkipTL returns data[2:] even if content is shorter — it only skips TL
		result, ok := derSkipTL([]byte{0x30, 0x0A})
		if !ok {
			t.Fatal("expected ok=true (derSkipTL only skips tag+length)")
		}
		// After 2-byte header with no content, rest is empty
		if len(result) != 0 {
			t.Errorf("expected empty rest, got %d bytes", len(result))
		}
	})
}

// TestDerSkipTLVEdgeCases covers long-form encoding and error paths.
func TestDerSkipTLVEdgeCases(t *testing.T) {
	t.Run("too short (< 2 bytes)", func(t *testing.T) {
		_, ok := derSkipTLV([]byte{0x02})
		if ok {
			t.Error("expected false for 1-byte input")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, ok := derSkipTLV([]byte{})
		if ok {
			t.Error("expected false for empty input")
		}
	})

	t.Run("short form end > len", func(t *testing.T) {
		// length=10 but only 2 bytes of content present → end > len(data)
		_, ok := derSkipTLV([]byte{0x02, 0x0A, 0x01, 0x02})
		if ok {
			t.Error("expected false when content extends past buffer")
		}
	})

	t.Run("long form valid", func(t *testing.T) {
		// INTEGER with 130-byte value: 0x02 0x81 0x82 <130 bytes>
		content := make([]byte, 130)
		for i := range content {
			content[i] = byte(i)
		}
		payload := append([]byte{0x02, 0x81, 0x82}, content...)
		// Append a marker byte after the TLV
		payload = append(payload, 0xFF)

		rest, ok := derSkipTLV(payload)
		if !ok {
			t.Fatal("expected success for long-form TLV")
		}
		if len(rest) != 1 || rest[0] != 0xFF {
			t.Errorf("expected rest=[0xFF], got %v", rest)
		}
	})

	t.Run("long form 2-byte length", func(t *testing.T) {
		// 0x04 0x82 0x01 0x00 = OCTET STRING 256 bytes
		content := make([]byte, 256)
		payload := append([]byte{0x04, 0x82, 0x01, 0x00}, content...)
		payload = append(payload, 0xAB) // marker

		rest, ok := derSkipTLV(payload)
		if !ok {
			t.Fatal("expected success for 2-byte long-form TLV")
		}
		if len(rest) != 1 || rest[0] != 0xAB {
			t.Errorf("expected rest=[0xAB], got %v", rest)
		}
	})

	t.Run("long form numBytes zero (indefinite)", func(t *testing.T) {
		_, ok := derSkipTLV([]byte{0x02, 0x80, 0x01, 0x02})
		if ok {
			t.Error("expected false for indefinite form")
		}
	})

	t.Run("long form numBytes > 4", func(t *testing.T) {
		_, ok := derSkipTLV([]byte{0x02, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05})
		if ok {
			t.Error("expected false for numBytes > 4")
		}
	})

	t.Run("long form end > len(data)", func(t *testing.T) {
		// 0x02 0x81 0x80 = INTEGER with 128 bytes, but only 10 bytes follow
		content := make([]byte, 10)
		payload := append([]byte{0x02, 0x81, 0x80}, content...)
		_, ok := derSkipTLV(payload)
		if ok {
			t.Error("expected false when TLV end overruns buffer")
		}
	})
}

// TestDerReadOctetStringEdgeCases covers wrong tag, long form, and error paths.
func TestDerReadOctetStringEdgeCases(t *testing.T) {
	t.Run("wrong tag (not 0x04)", func(t *testing.T) {
		_, _, ok := derReadOctetString([]byte{0x02, 0x01, 0x05}) // INTEGER
		if ok {
			t.Error("expected false for non-OCTET-STRING tag")
		}
	})

	t.Run("too short (< 2 bytes)", func(t *testing.T) {
		_, _, ok := derReadOctetString([]byte{0x04})
		if ok {
			t.Error("expected false for 1-byte input")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, _, ok := derReadOctetString([]byte{})
		if ok {
			t.Error("expected false for empty input")
		}
	})

	t.Run("short form end > len(data)", func(t *testing.T) {
		_, _, ok := derReadOctetString([]byte{0x04, 0x10, 0x01, 0x02}) // length=16 but only 2 bytes
		if ok {
			t.Error("expected false when content overruns buffer")
		}
	})

	t.Run("long form 1 byte (0x81)", func(t *testing.T) {
		content := make([]byte, 130)
		for i := range content {
			content[i] = byte(65 + i%26) // A-Z repeating
		}
		payload := append([]byte{0x04, 0x81, 130}, content...)
		payload = append(payload, 0x80) // context tag marker after

		val, rest, ok := derReadOctetString(payload)
		if !ok {
			t.Fatal("expected success for long-form OCTET STRING")
		}
		if !bytes.Equal(val, content) {
			t.Error("value mismatch")
		}
		if len(rest) != 1 || rest[0] != 0x80 {
			t.Errorf("unexpected rest: %v", rest)
		}
	})

	t.Run("long form 2 bytes (0x82)", func(t *testing.T) {
		content := make([]byte, 256)
		payload := append([]byte{0x04, 0x82, 0x01, 0x00}, content...)
		payload = append(payload, 0x99)

		val, rest, ok := derReadOctetString(payload)
		if !ok {
			t.Fatal("expected success for 2-byte long-form OCTET STRING")
		}
		if len(val) != 256 {
			t.Errorf("value length = %d, want 256", len(val))
		}
		if len(rest) != 1 || rest[0] != 0x99 {
			t.Errorf("unexpected rest: %v", rest)
		}
	})

	t.Run("long form numBytes zero (indefinite)", func(t *testing.T) {
		_, _, ok := derReadOctetString([]byte{0x04, 0x80, 0x01, 0x02})
		if ok {
			t.Error("expected false for indefinite form")
		}
	})

	t.Run("long form numBytes > 4", func(t *testing.T) {
		_, _, ok := derReadOctetString([]byte{0x04, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05})
		if ok {
			t.Error("expected false for numBytes > 4")
		}
	})

	t.Run("long form end > len(data)", func(t *testing.T) {
		// 0x04 0x81 0x80 = OCTET STRING claiming 128 bytes, but only 5 follow
		_, _, ok := derReadOctetString([]byte{0x04, 0x81, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05})
		if ok {
			t.Error("expected false when content extends past buffer")
		}
	})
}

// TestDerReadContextStringEdgeCases covers wrong tag, long form, and error paths.
func TestDerReadContextStringEdgeCases(t *testing.T) {
	t.Run("wrong tag (not 0x80)", func(t *testing.T) {
		_, _, ok := derReadContextString([]byte{0x04, 0x05, 'h', 'e', 'l', 'l', 'o'}) // OCTET STRING
		if ok {
			t.Error("expected false for non-0x80 tag")
		}
	})

	t.Run("too short (< 2 bytes)", func(t *testing.T) {
		_, _, ok := derReadContextString([]byte{0x80})
		if ok {
			t.Error("expected false for 1-byte input")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		_, _, ok := derReadContextString([]byte{})
		if ok {
			t.Error("expected false for empty input")
		}
	})

	t.Run("short form end > len(data)", func(t *testing.T) {
		// length=16 but only 2 content bytes present
		_, _, ok := derReadContextString([]byte{0x80, 0x10, 'a', 'b'})
		if ok {
			t.Error("expected false when content overruns buffer")
		}
	})

	t.Run("short form valid", func(t *testing.T) {
		payload := append([]byte{0x80, 0x06}, []byte("secret")...)
		payload = append(payload, 0xAA) // trailing marker

		val, rest, ok := derReadContextString(payload)
		if !ok {
			t.Fatal("expected success")
		}
		if string(val) != "secret" {
			t.Errorf("value = %q, want secret", string(val))
		}
		if len(rest) != 1 || rest[0] != 0xAA {
			t.Errorf("unexpected rest: %v", rest)
		}
	})

	t.Run("long form 1 byte (0x81)", func(t *testing.T) {
		content := make([]byte, 130)
		for i := range content {
			content[i] = byte('a' + i%26)
		}
		payload := append([]byte{0x80, 0x81, 130}, content...)
		payload = append(payload, 0xBB)

		val, rest, ok := derReadContextString(payload)
		if !ok {
			t.Fatal("expected success for long-form context string")
		}
		if !bytes.Equal(val, content) {
			t.Error("value mismatch")
		}
		if len(rest) != 1 || rest[0] != 0xBB {
			t.Errorf("unexpected rest: %v", rest)
		}
	})

	t.Run("long form numBytes zero (indefinite)", func(t *testing.T) {
		_, _, ok := derReadContextString([]byte{0x80, 0x80, 0x01, 0x02})
		if ok {
			t.Error("expected false for indefinite form")
		}
	})

	t.Run("long form numBytes > 4", func(t *testing.T) {
		_, _, ok := derReadContextString([]byte{0x80, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05})
		if ok {
			t.Error("expected false for numBytes > 4")
		}
	})

	t.Run("long form end > len(data)", func(t *testing.T) {
		// 0x80 0x81 0x80 = context string claiming 128 bytes, only 3 follow
		_, _, ok := derReadContextString([]byte{0x80, 0x81, 0x80, 0x01, 0x02, 0x03})
		if ok {
			t.Error("expected false when content overruns buffer")
		}
	})
}
