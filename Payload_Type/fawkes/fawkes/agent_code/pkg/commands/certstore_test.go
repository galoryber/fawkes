//go:build windows
// +build windows

package commands

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestCertFiletimeToTime_KnownDate(t *testing.T) {
	// 2026-01-01 00:00:00 UTC = FILETIME 133493280000000000
	// 133493280000000000 = 0x01DA5C80C3500000
	ft := windows.Filetime{
		LowDateTime:  0xC3500000,
		HighDateTime: 0x01DA5C80,
	}
	got := certFiletimeToTime(ft)
	want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if !got.Equal(want) {
		t.Errorf("certFiletimeToTime() = %v, want %v", got, want)
	}
}

func TestCertFiletimeToTime_Zero(t *testing.T) {
	ft := windows.Filetime{
		LowDateTime:  0,
		HighDateTime: 0,
	}
	got := certFiletimeToTime(ft)
	if !got.IsZero() {
		t.Errorf("certFiletimeToTime(zero) = %v, want zero time", got)
	}
}

func TestCertFiletimeToTime_Unix_Epoch(t *testing.T) {
	// Unix epoch (1970-01-01 00:00:00 UTC) = FILETIME 116444736000000000
	// 116444736000000000 = 0x019DB1DED53E8000
	ft := windows.Filetime{
		LowDateTime:  0xD53E8000,
		HighDateTime: 0x019DB1DE,
	}
	got := certFiletimeToTime(ft)
	want := time.Unix(0, 0).UTC()

	if !got.Equal(want) {
		t.Errorf("certFiletimeToTime(unix epoch) = %v, want %v", got, want)
	}
}

func TestGetStoreNames_Default(t *testing.T) {
	stores := getStoreNames("")
	if len(stores) != 5 {
		t.Errorf("getStoreNames(\"\") returned %d stores, want 5", len(stores))
	}
	// Should include MY, ROOT, CA, Trust, TrustedPeople
	expected := map[string]bool{"MY": true, "ROOT": true, "CA": true, "Trust": true, "TrustedPeople": true}
	for _, s := range stores {
		if !expected[s] {
			t.Errorf("unexpected store name: %q", s)
		}
	}
}

func TestGetStoreNames_All(t *testing.T) {
	stores := getStoreNames("all")
	if len(stores) != 5 {
		t.Errorf("getStoreNames(\"all\") returned %d stores, want 5", len(stores))
	}
}

func TestGetStoreNames_AllCaseInsensitive(t *testing.T) {
	stores := getStoreNames("ALL")
	if len(stores) != 5 {
		t.Errorf("getStoreNames(\"ALL\") returned %d stores, want 5", len(stores))
	}
}

func TestGetStoreNames_Specific(t *testing.T) {
	stores := getStoreNames("MY")
	if len(stores) != 1 || stores[0] != "MY" {
		t.Errorf("getStoreNames(\"MY\") = %v, want [MY]", stores)
	}
}

func TestGetStoreNames_Custom(t *testing.T) {
	stores := getStoreNames("CustomStore")
	if len(stores) != 1 || stores[0] != "CustomStore" {
		t.Errorf("getStoreNames(\"CustomStore\") = %v, want [CustomStore]", stores)
	}
}
