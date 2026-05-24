package commands

import (
	"strings"
	"testing"
)

func TestProxyDLLCSource_NamedExports(t *testing.T) {
	exports := []proxyExportEntry{
		{Ordinal: 1, Name: "CreateFileA"},
		{Ordinal: 2, Name: "ReadFile"},
		{Ordinal: 3, Name: "WriteFile"},
	}
	shellcode := []byte{0x90, 0x90, 0xC3}
	src := proxyDLLCSource(exports, "target_orig.dll", shellcode)

	if !strings.Contains(src, "0x90, 0x90, 0xC3") {
		t.Error("missing shellcode bytes")
	}
	if !strings.Contains(src, "DllMain") {
		t.Error("missing DllMain")
	}
	if !strings.Contains(src, "VirtualAlloc") {
		t.Error("missing VirtualAlloc")
	}
	if !strings.Contains(src, "#include <windows.h>") {
		t.Error("missing windows.h include")
	}
}

func TestProxyDLLCSource_OrdinalOnly(t *testing.T) {
	exports := []proxyExportEntry{
		{Ordinal: 5, Name: ""},
		{Ordinal: 10, Name: ""},
	}
	src := proxyDLLCSource(exports, "victim_orig.dll", []byte{0xCC})

	if !strings.Contains(src, "0xCC") {
		t.Error("missing shellcode byte")
	}
	if !strings.Contains(src, "DllMain") {
		t.Error("missing DllMain")
	}
}

func TestProxyDLLCSource_MixedExports(t *testing.T) {
	exports := []proxyExportEntry{
		{Ordinal: 1, Name: "Named"},
		{Ordinal: 2, Name: ""},
		{Ordinal: 3, Name: "Another", Forwarder: "ntdll.RtlExitProcess"},
	}
	src := proxyDLLCSource(exports, "lib_orig.dll", []byte{0x90})

	if !strings.Contains(src, "0x90") {
		t.Error("missing shellcode byte")
	}
	if !strings.Contains(src, "DllMain") {
		t.Error("missing DllMain")
	}
}

func TestProxyDLLCSource_EmptyShellcode(t *testing.T) {
	src := proxyDLLCSource(nil, "test_orig.dll", []byte{})
	if !strings.Contains(src, "payload[] = {\n}") {
		t.Error("empty shellcode should produce empty array")
	}
}

func TestProxyDLLCSource_LargeShellcode(t *testing.T) {
	sc := make([]byte, 48)
	for i := range sc {
		sc[i] = byte(i)
	}
	src := proxyDLLCSource(nil, "t.dll", sc)

	lines := strings.Split(src, "\n")
	var hexLines int
	for _, l := range lines {
		if strings.Contains(l, "0x") && strings.Contains(l, ",") {
			hexLines++
		}
	}
	if hexLines != 3 {
		t.Errorf("expected 3 hex lines for 48 bytes (16 per line), got %d", hexLines)
	}
}

func TestProxyDLLDEFFile_Named(t *testing.T) {
	exports := []proxyExportEntry{
		{Ordinal: 1, Name: "FuncA"},
		{Ordinal: 2, Name: "FuncB"},
	}
	def := proxyDLLDEFFile(exports, "orig.dll")

	if !strings.HasPrefix(def, "EXPORTS\n") {
		t.Error("DEF file should start with EXPORTS")
	}
	if !strings.Contains(def, "FuncA=orig.FuncA @1") {
		t.Error("missing FuncA forward")
	}
	if !strings.Contains(def, "FuncB=orig.FuncB @2") {
		t.Error("missing FuncB forward")
	}
}

func TestProxyDLLDEFFile_OrdinalOnly(t *testing.T) {
	exports := []proxyExportEntry{
		{Ordinal: 7, Name: ""},
	}
	def := proxyDLLDEFFile(exports, "target_orig.dll")

	if !strings.Contains(def, "noname_7=target_orig.#7 @7 NONAME") {
		t.Error("missing ordinal-only forward in DEF")
	}
}

func TestProxyDLLDEFFile_SkipsForwarders(t *testing.T) {
	exports := []proxyExportEntry{
		{Ordinal: 1, Name: "Real"},
		{Ordinal: 2, Name: "Forwarded", Forwarder: "other.Func"},
	}
	def := proxyDLLDEFFile(exports, "orig.dll")

	if !strings.Contains(def, "Real") {
		t.Error("real export should be present")
	}
	if strings.Contains(def, "Forwarded") {
		t.Error("forwarded export should be skipped")
	}
}

func TestProxyRenamedDLLName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"version.dll", "version_orig.dll"},
		{"CRYPTSP.DLL", "CRYPTSP_orig.dll"},
		{"wlbsctrl.dll", "wlbsctrl_orig.dll"},
		{"test", "test_orig.dll"},
	}
	for _, tc := range tests {
		got := proxyRenamedDLLName(tc.input)
		if got != tc.want {
			t.Errorf("proxyRenamedDLLName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestShellcodeFromHex(t *testing.T) {
	tests := []struct {
		input string
		want  []byte
		err   bool
	}{
		{"90 90 C3", []byte{0x90, 0x90, 0xC3}, false},
		{"0x90,0x90,0xC3", []byte{0x90, 0x90, 0xC3}, false},
		{"4883EC28", []byte{0x48, 0x83, 0xEC, 0x28}, false},
		{"", []byte{}, false},
		{"ZZ", nil, true},
	}
	for _, tc := range tests {
		got, err := shellcodeFromHex(tc.input)
		if tc.err {
			if err == nil {
				t.Errorf("shellcodeFromHex(%q) expected error", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("shellcodeFromHex(%q) error: %v", tc.input, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("shellcodeFromHex(%q) len=%d, want %d", tc.input, len(got), len(tc.want))
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("shellcodeFromHex(%q)[%d] = 0x%02X, want 0x%02X", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

func TestProxyDLLCSource_DLLNameWithoutExtension(t *testing.T) {
	exports := []proxyExportEntry{
		{Ordinal: 1, Name: "Test"},
	}
	src := proxyDLLCSource(exports, "mylib_orig", []byte{0xC3})

	if !strings.Contains(src, "0xC3") {
		t.Error("missing shellcode byte")
	}
	if !strings.Contains(src, "PayloadThread") {
		t.Error("missing PayloadThread function")
	}
}
