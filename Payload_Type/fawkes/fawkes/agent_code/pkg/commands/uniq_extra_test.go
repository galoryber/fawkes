package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// TestUniqOutputTruncation covers the `sb.Len() > maxOutput` truncation branch
// (line 92-95 in uniq.go) — triggered when output of unique lines exceeds 100 KB.
func TestUniqOutputTruncation(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "big.txt")

	// 1100 unique lines × ~93 chars each ≈ 102 KB output (exceeds 100 KB limit)
	var lines strings.Builder
	for i := 0; i < 1100; i++ {
		lines.WriteString(fmt.Sprintf("line%06d: %s\n", i, strings.Repeat("x", 80)))
	}
	if err := os.WriteFile(f, []byte(lines.String()), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := &UniqCommand{}
	result := cmd.Execute(structs.Task{Params: f})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "truncated") {
		t.Errorf("expected truncation notice, got output of length %d", len(result.Output))
	}
}
