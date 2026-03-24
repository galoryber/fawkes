package commands

import (
	"strings"
	"testing"
)

// --- daysToDate tests ---

func TestDaysToDate_UnixEpoch(t *testing.T) {
	y, m, d := daysToDate(0)
	if y != 1970 || m != 1 || d != 1 {
		t.Errorf("epoch: got %d-%02d-%02d, want 1970-01-01", y, m, d)
	}
}

func TestDaysToDate_KnownDates(t *testing.T) {
	tests := []struct {
		days             int64
		year, month, day int64
	}{
		{0, 1970, 1, 1},       // Unix epoch
		{365, 1971, 1, 1},     // One year
		{730, 1972, 1, 1},     // Two years
		{10957, 2000, 1, 1},   // Y2K
		{18628, 2021, 1, 1},   // 2021
		{19723, 2024, 1, 1},   // 2024 (leap year)
		{20454, 2026, 1, 1},   // 2026
		{20515, 2026, 3, 3},   // Today (roughly)
		{-1, 1969, 12, 31},    // Day before epoch
		{-365, 1969, 1, 1},    // One year before epoch
		{-719468, 0, 3, 1},    // Very early (astronomical year 0 = 1 BC)
	}
	for _, tt := range tests {
		y, m, d := daysToDate(tt.days)
		if y != tt.year || m != tt.month || d != tt.day {
			t.Errorf("daysToDate(%d) = %d-%02d-%02d, want %d-%02d-%02d",
				tt.days, y, m, d, tt.year, tt.month, tt.day)
		}
	}
}

func TestDaysToDate_LeapYears(t *testing.T) {
	// Feb 29, 2000 (leap year, day 60 of 2000)
	// 2000-01-01 = day 10957, so Feb 29 = 10957 + 59
	y, m, d := daysToDate(10957 + 59)
	if y != 2000 || m != 2 || d != 29 {
		t.Errorf("leap day 2000: got %d-%02d-%02d, want 2000-02-29", y, m, d)
	}

	// Feb 29, 2024 (leap year)
	// 2024-01-01 = day 19723, so Feb 29 = 19723 + 59
	y, m, d = daysToDate(19723 + 59)
	if y != 2024 || m != 2 || d != 29 {
		t.Errorf("leap day 2024: got %d-%02d-%02d, want 2024-02-29", y, m, d)
	}

	// Mar 1, 1900 (NOT a leap year — century rule)
	// 1900-01-01 = day -25567, Mar 1 = -25567 + 59
	y, m, d = daysToDate(-25567 + 59)
	if y != 1900 || m != 3 || d != 1 {
		t.Errorf("1900-03-01: got %d-%02d-%02d, want 1900-03-01", y, m, d)
	}
}

func TestDaysToDate_EndOfYear(t *testing.T) {
	// Dec 31, 2025 = 2026-01-01 (day 20454) - 1
	y, m, d := daysToDate(20453)
	if y != 2025 || m != 12 || d != 31 {
		t.Errorf("end of 2025: got %d-%02d-%02d, want 2025-12-31", y, m, d)
	}
}

func TestDaysToDate_NegativeDays(t *testing.T) {
	// Dates before Unix epoch (negative day values)
	y, m, d := daysToDate(-1)
	if y != 1969 || m != 12 || d != 31 {
		t.Errorf("day -1: got %d-%02d-%02d, want 1969-12-31", y, m, d)
	}

	// Very negative to exercise z < 0 branch: need days < -719468
	// This represents a date before ~0 AD. Day -720000 should be a valid ancient date.
	y, m, d = daysToDate(-720000)
	// Just verify it returns reasonable values (year < 0) without panicking
	if y > 0 {
		t.Errorf("day -720000: expected year <= 0, got %d-%02d-%02d", y, m, d)
	}
	if m < 1 || m > 12 || d < 1 || d > 31 {
		t.Errorf("day -720000: invalid month/day: %d-%02d-%02d", y, m, d)
	}
}

// --- windowsFileTimeToString tests ---

func TestWindowsFileTimeToString_Zero(t *testing.T) {
	if s := windowsFileTimeToString(0); s != "unknown" {
		t.Errorf("zero FILETIME: got %q, want %q", s, "unknown")
	}
}

func TestWindowsFileTimeToString_BeforeEpoch(t *testing.T) {
	// Value before Unix epoch diff (anything < 116444736000000000)
	if s := windowsFileTimeToString(100); s != "unknown" {
		t.Errorf("pre-epoch FILETIME: got %q, want %q", s, "unknown")
	}
}

func TestWindowsFileTimeToString_UnixEpoch(t *testing.T) {
	// Unix epoch = 1970-01-01 00:00:00
	const epochFT = 116444736000000000
	s := windowsFileTimeToString(epochFT)
	if s != "1970-01-01 00:00:00 UTC" {
		t.Errorf("Unix epoch: got %q, want %q", s, "1970-01-01 00:00:00 UTC")
	}
}

func TestWindowsFileTimeToString_KnownDate(t *testing.T) {
	// 2025-01-15 12:00:45 UTC
	// Unix timestamp: 1736942445
	// FILETIME = (1736942445 * 10000000) + 116444736000000000
	const ft = uint64(1736942445)*10000000 + 116444736000000000
	s := windowsFileTimeToString(ft)
	if s != "2025-01-15 12:00:45 UTC" {
		t.Errorf("2025-01-15: got %q, want %q", s, "2025-01-15 12:00:45 UTC")
	}
}

func TestWindowsFileTimeToString_Y2K(t *testing.T) {
	// 2000-01-01 00:00:00 UTC = Unix 946684800
	const ft = uint64(946684800)*10000000 + 116444736000000000
	s := windowsFileTimeToString(ft)
	if s != "2000-01-01 00:00:00 UTC" {
		t.Errorf("Y2K: got %q, want %q", s, "2000-01-01 00:00:00 UTC")
	}
}

func TestWindowsFileTimeToString_Format(t *testing.T) {
	// Any valid FILETIME should produce "YYYY-MM-DD HH:MM:SS UTC" format
	const ft = uint64(1000000000)*10000000 + 116444736000000000
	s := windowsFileTimeToString(ft)
	if !strings.HasSuffix(s, "UTC") {
		t.Errorf("should end with UTC: got %q", s)
	}
	if len(s) != len("2001-09-09 01:46:40 UTC") {
		t.Errorf("unexpected format length: got %q (len %d)", s, len(s))
	}
}

// --- nlgSidUsageString tests ---

func TestNlgSidUsageString_KnownTypes(t *testing.T) {
	tests := []struct {
		usage uint32
		want  string
	}{
		{1, "User"},
		{2, "Group"},
		{3, "Domain"},
		{4, "Alias"},
		{5, "WellKnownGroup"},
		{6, "DeletedAccount"},
		{9, "Computer"},
	}
	for _, tt := range tests {
		got := nlgSidUsageString(tt.usage)
		if got != tt.want {
			t.Errorf("nlgSidUsageString(%d) = %q, want %q", tt.usage, got, tt.want)
		}
	}
}

func TestNlgSidUsageString_UnknownTypes(t *testing.T) {
	unknowns := []uint32{0, 7, 8, 10, 100, 255}
	for _, u := range unknowns {
		got := nlgSidUsageString(u)
		if !strings.HasPrefix(got, "Type(") {
			t.Errorf("nlgSidUsageString(%d) = %q, want Type(...) format", u, got)
		}
	}
}

func TestNlgSidUsageString_Zero(t *testing.T) {
	got := nlgSidUsageString(0)
	if got != "Type(0)" {
		t.Errorf("nlgSidUsageString(0) = %q, want %q", got, "Type(0)")
	}
}
