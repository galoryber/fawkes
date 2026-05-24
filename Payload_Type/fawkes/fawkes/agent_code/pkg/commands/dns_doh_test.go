package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// --- dohTypeToNum ---

func TestDohTypeToNum_ValidTypes(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"A", 1},
		{"NS", 2},
		{"CNAME", 5},
		{"SOA", 6},
		{"PTR", 12},
		{"MX", 15},
		{"TXT", 16},
		{"AAAA", 28},
		{"SRV", 33},
		{"ANY", 255},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := dohTypeToNum(tc.input)
			if got != tc.want {
				t.Errorf("dohTypeToNum(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestDohTypeToNum_CaseInsensitive(t *testing.T) {
	if dohTypeToNum("a") != 1 {
		t.Error("expected case-insensitive match for 'a'")
	}
	if dohTypeToNum("aaaa") != 28 {
		t.Error("expected case-insensitive match for 'aaaa'")
	}
	if dohTypeToNum("Txt") != 16 {
		t.Error("expected case-insensitive match for 'Txt'")
	}
}

func TestDohTypeToNum_Invalid(t *testing.T) {
	if dohTypeToNum("INVALID") != 0 {
		t.Error("expected 0 for invalid type")
	}
	if dohTypeToNum("") != 0 {
		t.Error("expected 0 for empty type")
	}
}

// --- dohNumToType ---

func TestDohNumToType_KnownTypes(t *testing.T) {
	cases := []struct {
		input int
		want  string
	}{
		{1, "A"},
		{2, "NS"},
		{5, "CNAME"},
		{6, "SOA"},
		{12, "PTR"},
		{15, "MX"},
		{16, "TXT"},
		{28, "AAAA"},
		{33, "SRV"},
		{255, "ANY"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got := dohNumToType(tc.input)
			if got != tc.want {
				t.Errorf("dohNumToType(%d) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestDohNumToType_Unknown(t *testing.T) {
	got := dohNumToType(999)
	if got != "TYPE999" {
		t.Errorf("dohNumToType(999) = %q, want TYPE999", got)
	}
}

// --- dohProviderName ---

func TestDohProviderName_KnownProviders(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://cloudflare-dns.com/dns-query", "cloudflare"},
		{"https://dns.google/resolve", "google"},
		{"https://dns.quad9.net:5053/dns-query", "quad9"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got := dohProviderName(tc.url)
			if got != tc.want {
				t.Errorf("dohProviderName(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

func TestDohProviderName_CustomURL(t *testing.T) {
	got := dohProviderName("https://custom-doh.example.com/dns-query")
	if got != "custom-doh.example.com" {
		t.Errorf("got %q, want custom-doh.example.com", got)
	}
}

// --- formatDoHResult ---

func TestFormatDoHResult_Success(t *testing.T) {
	resp := &dohResponse{
		Status: 0,
		Answer: []dohAnswer{
			{Name: "example.com", Type: 1, TTL: 300, Data: "93.184.216.34"},
		},
	}
	args := dnsArgs{Target: "example.com"}
	result := formatDoHResult(args, "A", "https://cloudflare-dns.com/dns-query", resp)

	if result.Status != "success" {
		t.Errorf("status = %q, want success", result.Status)
	}
	if !strings.Contains(result.Output, "93.184.216.34") {
		t.Errorf("output missing IP address: %s", result.Output)
	}
	if !strings.Contains(result.Output, "cloudflare") {
		t.Errorf("output missing provider name: %s", result.Output)
	}
	if !strings.Contains(result.Output, "1 record") {
		t.Errorf("output missing record count: %s", result.Output)
	}
}

func TestFormatDoHResult_NXDOMAIN(t *testing.T) {
	resp := &dohResponse{Status: 3}
	args := dnsArgs{Target: "nonexistent.example.com"}
	result := formatDoHResult(args, "A", "https://dns.google/resolve", resp)

	if result.Status != "error" {
		t.Errorf("status = %q, want error for NXDOMAIN", result.Status)
	}
	if !strings.Contains(result.Output, "NXDOMAIN") {
		t.Errorf("output missing NXDOMAIN: %s", result.Output)
	}
}

func TestFormatDoHResult_NoRecords(t *testing.T) {
	resp := &dohResponse{Status: 0, Answer: nil}
	args := dnsArgs{Target: "example.com"}
	result := formatDoHResult(args, "MX", "https://cloudflare-dns.com/dns-query", resp)

	if result.Status != "success" {
		t.Errorf("status = %q, want success for empty answer", result.Status)
	}
	if !strings.Contains(result.Output, "no records") {
		t.Errorf("output missing 'no records': %s", result.Output)
	}
}

func TestFormatDoHResult_Truncated(t *testing.T) {
	resp := &dohResponse{
		Status: 0,
		TC:     true,
		Answer: []dohAnswer{{Name: "test.com", Type: 1, TTL: 60, Data: "1.2.3.4"}},
	}
	args := dnsArgs{Target: "test.com"}
	result := formatDoHResult(args, "A", "https://dns.google/resolve", resp)

	if !strings.Contains(result.Output, "truncated") {
		t.Errorf("output missing truncation warning: %s", result.Output)
	}
}

func TestFormatDoHResult_MultipleRecords(t *testing.T) {
	resp := &dohResponse{
		Status: 0,
		Answer: []dohAnswer{
			{Name: "example.com", Type: 1, TTL: 300, Data: "93.184.216.34"},
			{Name: "example.com", Type: 28, TTL: 300, Data: "2606:2800:220:1:248:1893:25c8:1946"},
		},
	}
	args := dnsArgs{Target: "example.com"}
	result := formatDoHResult(args, "A", "https://cloudflare-dns.com/dns-query", resp)

	if !strings.Contains(result.Output, "2 record") {
		t.Errorf("output missing record count: %s", result.Output)
	}
	if !strings.Contains(result.Output, "AAAA") {
		t.Errorf("output should show AAAA type for IPv6 record: %s", result.Output)
	}
}

func TestFormatDoHResult_AllRcodes(t *testing.T) {
	rcodes := map[int]string{
		1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
	}
	for code, name := range rcodes {
		resp := &dohResponse{Status: code}
		args := dnsArgs{Target: "test.com"}
		result := formatDoHResult(args, "A", "https://dns.google/resolve", resp)
		if !strings.Contains(result.Output, name) {
			t.Errorf("RCODE %d: output missing %q: %s", code, name, result.Output)
		}
	}
}

func TestFormatDoHResult_UnknownRcode(t *testing.T) {
	resp := &dohResponse{Status: 99}
	args := dnsArgs{Target: "test.com"}
	result := formatDoHResult(args, "A", "https://dns.google/resolve", resp)
	if !strings.Contains(result.Output, "RCODE_99") {
		t.Errorf("output missing RCODE_99: %s", result.Output)
	}
}

// --- dnsDoH integration edge cases ---

func TestDnsDoH_MissingTarget(t *testing.T) {
	cmd := &DnsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"doh"}`})
	if result.Status != "error" {
		t.Errorf("status = %q, want error for missing target", result.Status)
	}
}

func TestDnsDoH_InvalidType(t *testing.T) {
	cmd := &DnsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"doh","target":"example.com","data":"INVALID"}`})
	if result.Status != "error" {
		t.Errorf("status = %q, want error for invalid type", result.Status)
	}
	if !strings.Contains(result.Output, "unsupported record type") {
		t.Errorf("output = %q, want unsupported record type message", result.Output)
	}
}
