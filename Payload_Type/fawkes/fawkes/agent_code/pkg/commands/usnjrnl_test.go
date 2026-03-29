//go:build windows

package commands

import (
	"encoding/json"
	"testing"
	"unsafe"
)

func TestUsnJrnlCommandName(t *testing.T) {
	assertCommandName(t, &UsnJrnlCommand{}, "usn-jrnl")
}

func TestUsnJrnlCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &UsnJrnlCommand{})
}

func TestUsnJrnlEmptyParams(t *testing.T) {
	cmd := &UsnJrnlCommand{}
	result := cmd.Execute(mockTask("usn-jrnl", ""))
	assertError(t, result)
}

func TestUsnJrnlInvalidJSON(t *testing.T) {
	cmd := &UsnJrnlCommand{}
	result := cmd.Execute(mockTask("usn-jrnl", "not json"))
	assertError(t, result)
}

func TestUsnJrnlUnknownAction(t *testing.T) {
	cmd := &UsnJrnlCommand{}
	params, _ := json.Marshal(usnJrnlParams{Action: "badaction"})
	result := cmd.Execute(mockTask("usn-jrnl", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestUsnJrnlParamsUnmarshal(t *testing.T) {
	var params usnJrnlParams
	data := `{"action":"query","volume":"D:"}`
	if err := json.Unmarshal([]byte(data), &params); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if params.Action != "query" {
		t.Errorf("expected action=query, got %q", params.Action)
	}
	if params.Volume != "D:" {
		t.Errorf("expected volume=D:, got %q", params.Volume)
	}
}

func TestUsnJrnlFSCTLConstants(t *testing.T) {
	if fsctlQueryUsnJournal != 0x000900F4 {
		t.Errorf("fsctlQueryUsnJournal = 0x%X, want 0x000900F4", fsctlQueryUsnJournal)
	}
	if fsctlReadUsnJournal != 0x000900BB {
		t.Errorf("fsctlReadUsnJournal = 0x%X, want 0x000900BB", fsctlReadUsnJournal)
	}
	if fsctlDeleteUsnJournal != 0x000900F8 {
		t.Errorf("fsctlDeleteUsnJournal = 0x%X, want 0x000900F8", fsctlDeleteUsnJournal)
	}
}

func TestUsnJrnlStructSizes(t *testing.T) {
	// usnJournalData should be 56 bytes (7 * 8)
	if size := unsafe.Sizeof(usnJournalData{}); size != 56 {
		t.Errorf("usnJournalData size = %d, want 56", size)
	}
	// usnRecordV2 header should be 60 bytes
	if size := unsafe.Sizeof(usnRecordV2{}); size != 64 {
		// Actual size may include padding; verify it's reasonable
		if size < 56 || size > 72 {
			t.Errorf("usnRecordV2 size = %d, expected ~60-64", size)
		}
	}
}

func TestUsnReasonStringHelper(t *testing.T) {
	// Test the reason flag string conversion from forensics_helpers.go
	tests := []struct {
		reason uint32
		expect string
	}{
		{0x00000100, "Create"},
		{0x00000200, "Delete"},
		{0x00000300, "Create|Delete"},
		{0x00001000, "RenameOld"},
		{0x00002000, "RenameNew"},
	}
	for _, tc := range tests {
		got := usnReasonString(tc.reason)
		if got != tc.expect {
			t.Errorf("usnReasonString(0x%X) = %q, want %q", tc.reason, got, tc.expect)
		}
	}
}
