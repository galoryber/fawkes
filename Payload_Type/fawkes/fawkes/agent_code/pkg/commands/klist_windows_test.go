//go:build windows
// +build windows

package commands

import (
	"testing"
	"time"
)

func TestFiletimeToTimeKL(t *testing.T) {
	tests := []struct {
		name     string
		ft       int64
		wantZero bool
		wantYear int
		wantUnix int64
	}{
		{
			name:     "zero filetime",
			ft:       0,
			wantZero: true,
		},
		{
			name:     "epoch value",
			ft:       116444736000000000, // Windows epoch = Unix epoch
			wantZero: true,               // ft <= epoch returns zero
		},
		{
			name:     "one second after epoch",
			ft:       116444736000000000 + 10000000, // 1970-01-01 00:00:01
			wantUnix: 1,
		},
		{
			name:     "2023-01-01",
			ft:       133155552000000000, // 2023-01-01 00:00:00 UTC
			wantYear: 2023,
		},
		{
			name:     "negative filetime",
			ft:       -1,
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filetimeToTimeKL(tt.ft)
			if tt.wantZero {
				if !result.IsZero() {
					t.Errorf("expected zero time, got %v", result)
				}
				return
			}
			if tt.wantUnix != 0 {
				if result.Unix() != tt.wantUnix {
					t.Errorf("expected Unix %d, got %d", tt.wantUnix, result.Unix())
				}
			}
			if tt.wantYear != 0 {
				if result.Year() != tt.wantYear {
					t.Errorf("expected year %d, got %d", tt.wantYear, result.Year())
				}
			}
		})
	}
}

func TestFiletimeToTimeKLRoundtrip(t *testing.T) {
	// Convert a known time to filetime and back
	knownTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	const epoch int64 = 116444736000000000
	ft := knownTime.Unix()*10000000 + epoch

	result := filetimeToTimeKL(ft)
	if result.Year() != 2025 || result.Month() != 6 || result.Day() != 15 {
		t.Errorf("roundtrip failed: expected 2025-06-15, got %v", result)
	}
}

func TestLsaNtStatusToError(t *testing.T) {
	tests := []struct {
		name    string
		status  uintptr
		wantNil bool
		wantMsg string
	}{
		{
			name:    "success",
			status:  0,
			wantNil: true,
		},
		{
			name:    "access denied",
			status:  0xC0000022,
			wantMsg: "access denied",
		},
		{
			name:    "no logon servers",
			status:  0xC000005F,
			wantMsg: "no logon servers",
		},
		{
			name:    "object not found",
			status:  0xC0000034,
			wantMsg: "object not found",
		},
		{
			name:    "unknown status",
			status:  0xDEADBEEF,
			wantMsg: "NTSTATUS 0xDEADBEEF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lsaNtStatusToError(tt.status)
			if tt.wantNil {
				if err != nil {
					t.Errorf("expected nil error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
				return // unreachable, helps staticcheck
			}
			if !containsStr(err.Error(), tt.wantMsg) {
				t.Errorf("expected error containing %q, got %q", tt.wantMsg, err.Error())
			}
		})
	}
}
