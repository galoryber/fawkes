package commands

import (
	"encoding/binary"
	"testing"
)

func TestSniffExtractHTTPBasicAuth(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		wantUser string
		wantPass string
		wantNil  bool
	}{
		{
			name:     "valid basic auth",
			payload:  "GET /admin HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWRtaW46UEBzc3cwcmQ=\r\n\r\n",
			wantUser: "admin",
			wantPass: "P@ssw0rd",
		},
		{
			name:    "no auth header",
			payload: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantNil: true,
		},
		{
			name:    "too short",
			payload: "ab",
			wantNil: true,
		},
		{
			name:    "empty payload",
			payload: "",
			wantNil: true,
		},
		{
			name:     "POST with basic auth",
			payload:  "POST /api HTTP/1.1\r\nAuthorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n",
			wantUser: "user",
			wantPass: "secret",
		},
		{
			name:    "non-HTTP packet",
			payload: "\x00\x01\x02\x03random binary data",
			wantNil: true,
		},
	}

	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49000, DstPort: 80}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := sniffExtractHTTPBasicAuth([]byte(tt.payload), meta)
			if tt.wantNil {
				if cred != nil {
					t.Errorf("expected nil, got credential for user %q", cred.Username)
				}
				return
			}
			if cred == nil {
				t.Fatal("expected credential, got nil")
			}
			if cred.Username != tt.wantUser {
				t.Errorf("username = %q, want %q", cred.Username, tt.wantUser)
			}
			if cred.Password != tt.wantPass {
				t.Errorf("password = %q, want %q", cred.Password, tt.wantPass)
			}
			if cred.Protocol != "http-basic" {
				t.Errorf("protocol = %q, want http-basic", cred.Protocol)
			}
		})
	}
}

func TestSniffFTPTracker(t *testing.T) {
	ft := &sniffFTPTracker{pending: make(map[string]string)}
	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49000, DstPort: 21}

	// USER command should not return a credential
	cred := ft.process([]byte("USER ftpuser"), meta)
	if cred != nil {
		t.Error("USER alone should not produce a credential")
	}

	// PASS command should complete the credential
	cred = ft.process([]byte("PASS ftppass123"), meta)
	if cred == nil {
		t.Fatal("PASS after USER should produce a credential")
	}
	if cred.Username != "ftpuser" || cred.Password != "ftppass123" {
		t.Errorf("got user=%q pass=%q, want ftpuser/ftppass123", cred.Username, cred.Password)
	}

	// PASS without prior USER should not produce a credential
	cred = ft.process([]byte("PASS orphan"), meta)
	if cred != nil {
		t.Error("PASS without USER should not produce a credential")
	}

	// anonymous USER should be ignored
	cred = ft.process([]byte("USER anonymous"), meta)
	if cred != nil {
		t.Error("USER anonymous should be ignored")
	}
}

func TestSniffExtractNTLM(t *testing.T) {
	// Build a minimal NTLM Type 3 message
	buildNTLM3 := func(domain, user, host string) []byte {
		// NTLMSSP\0 signature + type 3
		msg := make([]byte, 200)
		copy(msg[0:8], "NTLMSSP\x00")
		binary.LittleEndian.PutUint32(msg[8:12], 3) // Type 3

		writeField := func(data string, lenOff, offOff, dataOff int) int {
			b := sniffTestEncodeUTF16LE(data)
			copy(msg[dataOff:], b)
			binary.LittleEndian.PutUint16(msg[lenOff:lenOff+2], uint16(len(b)))
			binary.LittleEndian.PutUint16(msg[lenOff+2:lenOff+4], uint16(len(b)))
			binary.LittleEndian.PutUint32(msg[offOff:offOff+4], uint32(dataOff))
			return len(b)
		}

		off := 72
		off += writeField(domain, 28, 32, off)
		off += writeField(user, 36, 40, off)
		writeField(host, 44, 48, off)

		return msg
	}

	meta := &packetMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 49000, DstPort: 445}

	t.Run("valid NTLM type 3", func(t *testing.T) {
		payload := buildNTLM3("CONTOSO", "jsmith", "WORKSTATION01")
		cred := sniffExtractNTLM(payload, meta)
		if cred == nil {
			t.Fatal("expected credential")
		}
		if cred.Username != "CONTOSO\\jsmith" {
			t.Errorf("username = %q, want CONTOSO\\jsmith", cred.Username)
		}
		if cred.Protocol != "ntlm" {
			t.Errorf("protocol = %q, want ntlm", cred.Protocol)
		}
	})

	t.Run("not NTLM", func(t *testing.T) {
		cred := sniffExtractNTLM([]byte("random data"), meta)
		if cred != nil {
			t.Error("expected nil for non-NTLM data")
		}
	})

	t.Run("NTLM type 1 ignored", func(t *testing.T) {
		msg := make([]byte, 80)
		copy(msg[0:8], "NTLMSSP\x00")
		binary.LittleEndian.PutUint32(msg[8:12], 1) // Type 1
		cred := sniffExtractNTLM(msg, meta)
		if cred != nil {
			t.Error("Type 1 should be ignored")
		}
	})
}

func sniffTestEncodeUTF16LE(s string) []byte {
	b := make([]byte, len(s)*2)
	for i, c := range s {
		binary.LittleEndian.PutUint16(b[i*2:], uint16(c))
	}
	return b
}

func TestSniffExtractKerberos(t *testing.T) {
	// Helper to build a minimal ASN.1 DER Kerberos AS-REP
	buildASREP := func(realm, principal string) []byte {
		// Build cname: PrincipalName SEQUENCE { [0] INTEGER 1, [1] SEQUENCE { GeneralString } }
		nameStr := asn1String(0x1B, principal)
		nameSeqOf := asn1Wrap(0x30, nameStr)
		nameTag1 := asn1Wrap(0xA1, nameSeqOf)
		nameType := asn1Wrap(0xA0, asn1Integer(1))
		cname := asn1Wrap(0x30, append(nameType, nameTag1...))

		// Build body fields
		pvno := asn1Wrap(0xA0, asn1Integer(5))
		msgType := asn1Wrap(0xA1, asn1Integer(11))
		crealm := asn1Wrap(0xA3, asn1String(0x1B, realm))
		cnameTag := asn1Wrap(0xA4, cname)

		// Minimal ticket placeholder [5] and enc-part [6]
		ticket := asn1Wrap(0xA5, asn1Wrap(0x61, asn1Wrap(0x30, []byte{0x02, 0x01, 0x05})))
		encPart := asn1Wrap(0xA6, asn1Wrap(0x30, []byte{0x02, 0x01, 0x17}))

		body := append(pvno, msgType...)
		body = append(body, crealm...)
		body = append(body, cnameTag...)
		body = append(body, ticket...)
		body = append(body, encPart...)

		seq := asn1Wrap(0x30, body)
		return asn1Wrap(0x6B, seq) // Application tag 11
	}

	meta := &packetMeta{SrcIP: "192.168.1.10", SrcPort: 88, DstIP: "192.168.1.50", DstPort: 49900}

	t.Run("valid AS-REP", func(t *testing.T) {
		payload := buildASREP("CONTOSO.COM", "jdoe")
		cred := sniffExtractKerberos(payload, meta)
		if cred == nil {
			t.Fatal("expected credential from AS-REP")
		}
		if cred.Protocol != "krb-asrep" {
			t.Errorf("protocol = %q, want krb-asrep", cred.Protocol)
		}
		if cred.Username != "jdoe@CONTOSO.COM" {
			t.Errorf("username = %q, want jdoe@CONTOSO.COM", cred.Username)
		}
	})

	t.Run("with TCP framing", func(t *testing.T) {
		inner := buildASREP("DOMAIN.LOCAL", "admin")
		framed := make([]byte, 4+len(inner))
		binary.BigEndian.PutUint32(framed[0:4], uint32(len(inner)))
		copy(framed[4:], inner)
		cred := sniffExtractKerberos(framed, meta)
		if cred == nil {
			t.Fatal("expected credential from TCP-framed AS-REP")
		}
		if cred.Username != "admin@DOMAIN.LOCAL" {
			t.Errorf("username = %q, want admin@DOMAIN.LOCAL", cred.Username)
		}
	})

	t.Run("wrong port", func(t *testing.T) {
		payload := buildASREP("TEST.COM", "user1")
		wrongMeta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 80, DstIP: "10.0.0.2", DstPort: 443}
		cred := sniffExtractKerberos(payload, wrongMeta)
		if cred != nil {
			t.Error("expected nil for non-Kerberos port")
		}
	})

	t.Run("not Kerberos", func(t *testing.T) {
		cred := sniffExtractKerberos([]byte("GET / HTTP/1.1\r\n"), meta)
		if cred != nil {
			t.Error("expected nil for non-Kerberos data")
		}
	})

	t.Run("too short", func(t *testing.T) {
		cred := sniffExtractKerberos([]byte{0x6B, 0x03, 0x30}, meta)
		if cred != nil {
			t.Error("expected nil for truncated data")
		}
	})
}

func TestSniffASN1Helpers(t *testing.T) {
	t.Run("short form length", func(t *testing.T) {
		l, n := sniffASN1Len([]byte{42})
		if l != 42 || n != 1 {
			t.Errorf("got len=%d, bytes=%d; want 42, 1", l, n)
		}
	})

	t.Run("long form length 1 byte", func(t *testing.T) {
		l, n := sniffASN1Len([]byte{0x81, 0xC0})
		if l != 192 || n != 2 {
			t.Errorf("got len=%d, bytes=%d; want 192, 2", l, n)
		}
	})

	t.Run("long form length 2 bytes", func(t *testing.T) {
		l, n := sniffASN1Len([]byte{0x82, 0x01, 0x00})
		if l != 256 || n != 3 {
			t.Errorf("got len=%d, bytes=%d; want 256, 3", l, n)
		}
	})

	t.Run("empty data", func(t *testing.T) {
		l, n := sniffASN1Len([]byte{})
		if l != -1 || n != 0 {
			t.Errorf("got len=%d, bytes=%d; want -1, 0", l, n)
		}
	})

	t.Run("skip valid TLV", func(t *testing.T) {
		data := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
		content, ok := sniffASN1Skip(data, 0x30)
		if !ok || len(content) != 3 {
			t.Errorf("skip failed: ok=%v, len=%d", ok, len(content))
		}
	})

	t.Run("skip wrong tag", func(t *testing.T) {
		data := []byte{0x31, 0x03, 0x01, 0x02, 0x03}
		_, ok := sniffASN1Skip(data, 0x30)
		if ok {
			t.Error("expected failure for wrong tag")
		}
	})
}

func TestSniffDecodeUTF16LE(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"hello", []byte{0x48, 0x00, 0x69, 0x00}, "Hi"},
		{"empty", []byte{}, ""},
		{"odd bytes", []byte{0x48}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sniffDecodeUTF16LE(tt.in)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// ASN.1 DER helpers for building test data

func asn1Wrap(tag byte, content []byte) []byte {
	l := len(content)
	if l < 128 {
		return append([]byte{tag, byte(l)}, content...)
	}
	if l < 256 {
		return append([]byte{tag, 0x81, byte(l)}, content...)
	}
	return append([]byte{tag, 0x82, byte(l >> 8), byte(l)}, content...)
}

func asn1String(tag byte, s string) []byte {
	return asn1Wrap(tag, []byte(s))
}

func asn1Integer(v int) []byte {
	return []byte{0x02, 0x01, byte(v)}
}
