//go:build windows

package commands

import (
	"strings"
	"testing"
)

func TestKnownEDRMinifiltersDatabase(t *testing.T) {
	if len(knownEDRMinifilters) < 20 {
		t.Errorf("knownEDRMinifilters has %d entries, want at least 20", len(knownEDRMinifilters))
	}

	for name, info := range knownEDRMinifilters {
		if name != strings.ToLower(name) {
			t.Errorf("minifilter key %q is not lowercase", name)
		}
		if info.vendor == "" {
			t.Errorf("minifilter %q has empty vendor", name)
		}
		if info.product == "" {
			t.Errorf("minifilter %q has empty product", name)
		}
	}
}

func TestClassifyMinifilter(t *testing.T) {
	tests := []struct {
		name       string
		wantVendor string
		wantProd   string
	}{
		{"csagent", "CrowdStrike", "Falcon"},
		{"WdFilter", "Microsoft", "Defender"},
		{"sentinelmonitor", "SentinelOne", "SentinelOne"},
		{"unknowndriver", "", ""},
	}

	for _, tt := range tests {
		fi := &minifilterInfo{Name: tt.name}
		classifyMinifilter(fi)
		if fi.EDRVendor != tt.wantVendor {
			t.Errorf("classifyMinifilter(%q) vendor = %q, want %q", tt.name, fi.EDRVendor, tt.wantVendor)
		}
		if fi.EDRProduct != tt.wantProd {
			t.Errorf("classifyMinifilter(%q) product = %q, want %q", tt.name, fi.EDRProduct, tt.wantProd)
		}
	}
}

func TestParseFilterFullInfo(t *testing.T) {
	buf := make([]byte, 100)
	buf[4] = 0x01
	buf[8] = 0x03
	nameUTF16 := encodeUTF16LE("TestFilter")
	nameLen := len(nameUTF16)
	buf[12] = byte(nameLen)
	buf[13] = byte(nameLen >> 8)
	copy(buf[14:], nameUTF16)

	fi := parseFilterFullInfo(buf[:14+nameLen])
	if fi == nil {
		t.Fatal("parseFilterFullInfo returned nil")
	}
	if fi.Name != "TestFilter" {
		t.Errorf("Name = %q, want %q", fi.Name, "TestFilter")
	}
	if fi.FrameID != 1 {
		t.Errorf("FrameID = %d, want 1", fi.FrameID)
	}
	if fi.Instances != 3 {
		t.Errorf("Instances = %d, want 3", fi.Instances)
	}
}

func TestParseFilterFullInfoTooShort(t *testing.T) {
	fi := parseFilterFullInfo(make([]byte, 10))
	if fi != nil {
		t.Error("expected nil for too-short buffer")
	}
}

