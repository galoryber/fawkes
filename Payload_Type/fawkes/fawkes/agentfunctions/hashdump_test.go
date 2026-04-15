package agentfunctions

import (
	"testing"
)

func TestParseHashdumpEntries_StandardSAM(t *testing.T) {
	input := `Administrator:500:aad3b435b51404ee:8846f7eaee8fb117:::
Guest:501:aad3b435b51404ee:31d6cfe0d16ae931:::
DefaultAccount:503:aad3b435b51404ee:31d6cfe0d16ae931:::
WDAGUtilityAccount:504:aad3b435b51404ee:abcdef1234567890:::`

	entries := parseHashdumpEntries(input)
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	if entries[0].Username != "Administrator" {
		t.Errorf("expected Administrator, got %q", entries[0].Username)
	}
	if entries[0].Hash != "8846f7eaee8fb117" {
		t.Errorf("expected NT hash 8846f7eaee8fb117, got %q", entries[0].Hash)
	}
}

func TestParseHashdumpEntries_SkipsMachineAccounts(t *testing.T) {
	input := `Administrator:500:aad3b435b51404ee:8846f7eaee8fb117:::
WORKSTATION$:1000:aad3b435b51404ee:deadbeef12345678:::
DOMAIN$:1001:aad3b435b51404ee:cafebabe12345678:::`

	entries := parseHashdumpEntries(input)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (machine accounts skipped), got %d", len(entries))
	}
	if entries[0].Username != "Administrator" {
		t.Errorf("expected Administrator, got %q", entries[0].Username)
	}
}

func TestParseHashdumpEntries_SkipsZeroHashes(t *testing.T) {
	input := `Administrator:500:aad3b435b51404ee:8846f7eaee8fb117:::
DisabledUser:501:aad3b435b51404ee:00000000000000000000000000000000:::`

	entries := parseHashdumpEntries(input)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (zero hash skipped), got %d", len(entries))
	}
}

func TestParseHashdumpEntries_DeduplicatesEntries(t *testing.T) {
	input := `Administrator:500:aad3b435b51404ee:8846f7eaee8fb117:::
Administrator:500:aad3b435b51404ee:8846f7eaee8fb117:::`

	entries := parseHashdumpEntries(input)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (deduplication), got %d", len(entries))
	}
}

func TestParseHashdumpEntries_EmptyInput(t *testing.T) {
	entries := parseHashdumpEntries("")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from empty input, got %d", len(entries))
	}
}

func TestParseHashdumpEntries_MalformedLines(t *testing.T) {
	input := `Administrator:500:aad3b435b51404ee:8846f7eaee8fb117:::
this is not a hash line
:500:aad3b435b51404ee:abcdef:::
short:line`

	entries := parseHashdumpEntries(input)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (malformed lines skipped), got %d", len(entries))
	}
}

func TestParseHashdumpEntries_EmptyUsernameOrHash(t *testing.T) {
	input := `:500:aad3b435b51404ee:8846f7eaee8fb117:::
user:500:aad3b435b51404ee:::::`

	entries := parseHashdumpEntries(input)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries (empty username or hash), got %d", len(entries))
	}
}

func TestParseHashdumpEntries_WhitespaceHandling(t *testing.T) {
	input := `  Administrator:500:aad3b435b51404ee:8846f7eaee8fb117:::

  Guest:501:aad3b435b51404ee:31d6cfe0d16ae931:::  `

	entries := parseHashdumpEntries(input)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries with whitespace trimming, got %d", len(entries))
	}
}
