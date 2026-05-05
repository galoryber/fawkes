package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// TestTacOutputTruncation covers the `len(out) > 100000` truncation branch
// (line 52-54 in tac.go) — triggered when reversed file output exceeds 100 KB.
func TestTacOutputTruncation(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "big.txt")

	// 1100 lines × 94 chars each ≈ 103 KB output (exceeds 100 KB limit)
	var lines strings.Builder
	for i := 0; i < 1100; i++ {
		lines.WriteString(strings.Repeat("x", 93) + "\n")
	}
	if err := os.WriteFile(f, []byte(lines.String()), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := &TacCommand{}
	result := cmd.Execute(structs.Task{Params: f})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "truncated") {
		t.Errorf("expected truncation notice, got output of length %d", len(result.Output))
	}
}
