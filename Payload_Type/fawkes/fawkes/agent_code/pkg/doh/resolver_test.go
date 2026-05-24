package doh

import (
	"testing"
)

func TestResolveEndpoint_KnownProviders(t *testing.T) {
	tests := []struct {
		provider string
		want     string
	}{
		{"cloudflare", "https://cloudflare-dns.com/dns-query"},
		{"google", "https://dns.google/resolve"},
		{"quad9", "https://dns.quad9.net:5053/dns-query"},
		{"CLOUDFLARE", "https://cloudflare-dns.com/dns-query"},
		{"Google", "https://dns.google/resolve"},
	}
	for _, tt := range tests {
		got := resolveEndpoint(tt.provider)
		if got != tt.want {
			t.Errorf("resolveEndpoint(%q) = %q, want %q", tt.provider, got, tt.want)
		}
	}
}

func TestResolveEndpoint_CustomURL(t *testing.T) {
	url := "https://custom-dns.example.com/dns-query"
	got := resolveEndpoint(url)
	if got != url {
		t.Errorf("resolveEndpoint(custom URL) = %q, want %q", got, url)
	}
}

func TestResolveEndpoint_Hostname(t *testing.T) {
	got := resolveEndpoint("dns.example.com")
	want := "https://dns.example.com/dns-query"
	if got != want {
		t.Errorf("resolveEndpoint(hostname) = %q, want %q", got, want)
	}
}

func TestReverseAddr_IPv4(t *testing.T) {
	got, err := reverseAddr("192.168.1.1")
	if err != nil {
		t.Fatalf("reverseAddr error: %v", err)
	}
	want := "1.1.168.192.in-addr.arpa"
	if got != want {
		t.Errorf("reverseAddr(192.168.1.1) = %q, want %q", got, want)
	}
}

func TestReverseAddr_InvalidIP(t *testing.T) {
	_, err := reverseAddr("not-an-ip")
	if err == nil {
		t.Error("Expected error for invalid IP")
	}
}

func TestEncodeDNSName(t *testing.T) {
	got := encodeDNSName("example.com")
	// Expected: 7 "example" 3 "com" 0
	want := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	if len(got) != len(want) {
		t.Fatalf("encodeDNSName length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("encodeDNSName byte %d = 0x%02x, want 0x%02x", i, got[i], want[i])
		}
	}
}

func TestEncodeDNSName_Subdomain(t *testing.T) {
	got := encodeDNSName("sub.example.com")
	// Expected: 3 "sub" 7 "example" 3 "com" 0
	if got[0] != 3 || got[4] != 7 || got[12] != 3 {
		t.Errorf("encodeDNSName label lengths wrong: got %v", got)
	}
	if got[len(got)-1] != 0 {
		t.Error("encodeDNSName should end with null byte")
	}
}

func TestParseDNSQuestion_Simple(t *testing.T) {
	// Build a DNS question for "test.com" type A
	data := encodeDNSName("test.com")
	data = append(data, 0, 1) // TYPE A
	data = append(data, 0, 1) // CLASS IN

	name, qtype, offset := parseDNSQuestion(data)
	if name != "test.com" {
		t.Errorf("name = %q, want test.com", name)
	}
	if qtype != 1 {
		t.Errorf("qtype = %d, want 1 (A)", qtype)
	}
	if offset < 10 {
		t.Errorf("offset = %d, expected >= 10", offset)
	}
}

func TestParseDNSQuestion_AAAA(t *testing.T) {
	data := encodeDNSName("ipv6.example.com")
	data = append(data, 0, 28) // TYPE AAAA
	data = append(data, 0, 1)  // CLASS IN

	name, qtype, _ := parseDNSQuestion(data)
	if name != "ipv6.example.com" {
		t.Errorf("name = %q", name)
	}
	if qtype != 28 {
		t.Errorf("qtype = %d, want 28 (AAAA)", qtype)
	}
}

func TestBuildDNSResponse_SingleA(t *testing.T) {
	resp := buildDNSResponse(0x1234, "test.com", 1, []string{"1.2.3.4"})
	if len(resp) < 12 {
		t.Fatal("response too short")
	}
	// Check transaction ID
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Errorf("txID = 0x%02x%02x, want 0x1234", resp[0], resp[1])
	}
	// Check QR bit (response)
	if resp[2]&0x80 == 0 {
		t.Error("QR bit not set (should be a response)")
	}
	// Check answer count
	if resp[7] != 1 {
		t.Errorf("ANCOUNT = %d, want 1", resp[7])
	}
}

func TestBuildDNSResponse_NoAnswers(t *testing.T) {
	resp := buildDNSResponse(0x0001, "test.com", 1, nil)
	if resp[7] != 0 {
		t.Errorf("ANCOUNT = %d, want 0 for no answers", resp[7])
	}
}

func TestBuildDNSResponse_MultipleA(t *testing.T) {
	resp := buildDNSResponse(0x0001, "test.com", 1, []string{"1.1.1.1", "2.2.2.2"})
	if resp[7] != 2 {
		t.Errorf("ANCOUNT = %d, want 2", resp[7])
	}
}

func TestSetGlobalResolver(t *testing.T) {
	// Just verify it doesn't panic and sets the state
	SetGlobalResolver("cloudflare")
	if !IsEnabled() {
		t.Error("IsEnabled() should be true after SetGlobalResolver")
	}
	if Endpoint() != "https://cloudflare-dns.com/dns-query" {
		t.Errorf("Endpoint() = %q", Endpoint())
	}
}

func TestIsEnabled_Default(t *testing.T) {
	// Reset state
	dohDialer.enabled = false
	dohDialer.endpoint = ""
	if IsEnabled() {
		t.Error("IsEnabled() should be false by default")
	}
	// Restore
	SetGlobalResolver("cloudflare")
}
