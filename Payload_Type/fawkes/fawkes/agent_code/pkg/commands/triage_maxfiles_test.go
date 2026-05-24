package commands

import (
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

// TestTriageAllMaxFilesEarlyReturn covers the `len(results) >= args.MaxFiles` early-return
// branches in triageAll (lines 123-125 and 127-129) — triggered when documents alone
// fill the MaxFiles quota, preventing credentials and configs from being scanned.
func TestTriageAllMaxFilesEarlyReturn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create a PDF in the home dir (Linux triageDocuments includes home itself as a search path)
	docs := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docs, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docs, "important.pdf"), []byte("pdf content"), 0644); err != nil {
		t.Fatal(err)
	}

	task := structs.NewTask("t", "triage", "")
	// MaxFiles=1 means after finding the first document the early-return triggers
	args := triageArgs{MaxSize: 1024 * 1024, MaxFiles: 1}

	results := triageAll(task, args)
	// We should get results (the early return was reached because len >= MaxFiles)
	// The important thing is the function returned without panicking and respects the limit
	if len(results) > args.MaxFiles {
		t.Errorf("expected at most %d results, got %d", args.MaxFiles, len(results))
	}
}

// TestTriageAllMaxFilesSecondEarlyReturn covers the second early-return (line 127-129)
// in triageAll — triggered when documents + credentials together hit MaxFiles,
// preventing configs from being scanned.
func TestTriageAllMaxFilesSecondEarlyReturn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create a credential-pattern file (id_rsa) and a document
	if err := os.WriteFile(filepath.Join(home, "id_rsa"), []byte("ssh-rsa key"), 0644); err != nil {
		t.Fatal(err)
	}

	task := structs.NewTask("t", "triage", "")
	// MaxFiles=0 is replaced with 200 by Execute, but triageAll is called directly here.
	// Use MaxFiles=1 to ensure credential scan alone triggers the second check.
	args := triageArgs{MaxSize: 1024 * 1024, MaxFiles: 1}

	results := triageAll(task, args)
	if len(results) > args.MaxFiles {
		t.Errorf("expected at most %d results, got %d", args.MaxFiles, len(results))
	}
}
