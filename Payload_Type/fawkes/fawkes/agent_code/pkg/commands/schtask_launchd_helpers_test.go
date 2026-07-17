package commands

import (
	"testing"
)

func TestParseLaunchdListOutput_Normal(t *testing.T) {
	output := `PID	Status	Label
-	0	com.apple.Spotlight
123	0	com.apple.WindowServer
-	78	com.apple.systemstats
456	0	com.company.agent
`
	results := parseLaunchdListOutput(output)
	if len(results) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(results))
	}

	want := []launchdEntry{
		{"-", "0", "com.apple.Spotlight"},
		{"123", "0", "com.apple.WindowServer"},
		{"-", "78", "com.apple.systemstats"},
		{"456", "0", "com.company.agent"},
	}
	for i, w := range want {
		if results[i] != w {
			t.Errorf("entry %d: got %+v, want %+v", i, results[i], w)
		}
	}
}

func TestParseLaunchdListOutput_Empty(t *testing.T) {
	results := parseLaunchdListOutput("")
	if len(results) != 0 {
		t.Errorf("empty input should return 0 entries, got %d", len(results))
	}
}

func TestParseLaunchdListOutput_HeaderOnly(t *testing.T) {
	results := parseLaunchdListOutput("PID\tStatus\tLabel\n")
	if len(results) != 0 {
		t.Errorf("header-only input should return 0 entries, got %d", len(results))
	}
}

func TestParseLaunchdListOutput_SkipsShortLines(t *testing.T) {
	output := "PID\tStatus\tLabel\n-\t0\n\n-\t0\tcom.test\n"
	results := parseLaunchdListOutput(output)
	if len(results) != 1 {
		t.Fatalf("expected 1 entry (skipping short line), got %d", len(results))
	}
	if results[0].Label != "com.test" {
		t.Errorf("expected label com.test, got %s", results[0].Label)
	}
}

func TestParseLaunchdListOutput_NonZeroStatus(t *testing.T) {
	output := "-\t127\tcom.example.crashed\n789\t0\tcom.example.running\n"
	results := parseLaunchdListOutput(output)
	if len(results) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(results))
	}
	if results[0].Status != "127" {
		t.Errorf("expected status 127, got %s", results[0].Status)
	}
	if results[1].PID != "789" {
		t.Errorf("expected PID 789, got %s", results[1].PID)
	}
}

func TestParseLaunchdListOutput_WhitespaceVariants(t *testing.T) {
	output := "  -   0   com.apple.test  \n123   0   com.apple.other\n"
	results := parseLaunchdListOutput(output)
	if len(results) != 2 {
		t.Fatalf("expected 2 entries with space-separated fields, got %d", len(results))
	}
	if results[0].Label != "com.apple.test" {
		t.Errorf("expected com.apple.test, got %s", results[0].Label)
	}
}
