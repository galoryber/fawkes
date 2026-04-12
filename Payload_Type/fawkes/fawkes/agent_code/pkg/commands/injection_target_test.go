package commands

import (
	"testing"
)

func TestScoreProcessExcludesSelf(t *testing.T) {
	p := ProcessInfo{PID: 1234, Name: "explorer.exe", Arch: "x64"}
	result := scoreProcess(p, 1234, "x64", "user", 2, TargetAuto)
	if result != nil {
		t.Error("should exclude self PID")
	}
}

func TestScoreProcessExcludesCritical(t *testing.T) {
	critical := []string{"lsass.exe", "csrss.exe", "smss.exe", "services.exe", "System"}
	for _, name := range critical {
		p := ProcessInfo{PID: 500, Name: name, Arch: "x64"}
		result := scoreProcess(p, 1000, "x64", "user", 2, TargetAuto)
		if result != nil {
			t.Errorf("should exclude critical process %s", name)
		}
	}
}

func TestScoreProcessExcludesEDR(t *testing.T) {
	edr := []string{"MsMpEng.exe", "CSFalconService.exe", "SentinelAgent.exe", "cb.exe"}
	for _, name := range edr {
		p := ProcessInfo{PID: 600, Name: name, Arch: "x64"}
		result := scoreProcess(p, 1000, "x64", "user", 2, TargetAuto)
		if result != nil {
			t.Errorf("should exclude EDR process %s", name)
		}
	}
}

func TestScoreProcessExcludesLowPID(t *testing.T) {
	for _, pid := range []int32{0, 4} {
		p := ProcessInfo{PID: pid, Name: "idle", Arch: "x64"}
		result := scoreProcess(p, 1000, "x64", "user", 2, TargetAuto)
		if result != nil {
			t.Errorf("should exclude PID %d", pid)
		}
	}
}

func TestScoreProcessArchMismatchExcluded(t *testing.T) {
	p := ProcessInfo{PID: 500, Name: "notepad.exe", Arch: "x86"}
	result := scoreProcess(p, 1000, "x64", "user", 2, TargetAuto)
	if result != nil {
		t.Error("should exclude arch mismatch (x86 target with x64 agent)")
	}
}

func TestScoreProcessCommonBonus(t *testing.T) {
	explorer := ProcessInfo{PID: 500, Name: "explorer.exe", Arch: "x64", User: "testuser", IntegrityLevel: 2}
	result := scoreProcess(explorer, 1000, "x64", "testuser", 2, TargetAuto)
	if result == nil {
		t.Fatal("explorer.exe should be scored")
	}
	if result.Score < 80 {
		t.Errorf("explorer.exe should score high (same user + common + arch match), got %d", result.Score)
	}

	// Compare with uncommon process
	uncommon := ProcessInfo{PID: 600, Name: "random.exe", Arch: "x64", User: "testuser", IntegrityLevel: 2}
	uncommonResult := scoreProcess(uncommon, 1000, "x64", "testuser", 2, TargetAuto)
	if uncommonResult == nil {
		t.Fatal("random.exe should be scored")
	}
	if uncommonResult.Score >= result.Score {
		t.Errorf("explorer.exe (%d) should score higher than random.exe (%d)", result.Score, uncommonResult.Score)
	}
}

func TestScoreProcessSameUserBonus(t *testing.T) {
	sameUser := ProcessInfo{PID: 500, Name: "notepad.exe", Arch: "x64", User: "testuser", IntegrityLevel: 2}
	diffUser := ProcessInfo{PID: 600, Name: "notepad.exe", Arch: "x64", User: "SYSTEM", IntegrityLevel: 4}

	same := scoreProcess(sameUser, 1000, "x64", "testuser", 2, TargetAutoUser)
	diff := scoreProcess(diffUser, 1000, "x64", "testuser", 2, TargetAutoUser)

	if same == nil || diff == nil {
		t.Fatal("both should be scored")
	}
	if same.Score <= diff.Score {
		t.Errorf("same user (%d) should score higher than diff user (%d) in auto-user mode", same.Score, diff.Score)
	}
}

func TestScoreProcessAutoElevated(t *testing.T) {
	system := ProcessInfo{PID: 500, Name: "dllhost.exe", Arch: "x64", User: "SYSTEM", IntegrityLevel: 4}
	medium := ProcessInfo{PID: 600, Name: "dllhost.exe", Arch: "x64", User: "testuser", IntegrityLevel: 2}

	sys := scoreProcess(system, 1000, "x64", "testuser", 3, TargetAutoElevated)
	med := scoreProcess(medium, 1000, "x64", "testuser", 3, TargetAutoElevated)

	if sys == nil || med == nil {
		t.Fatal("both should be scored")
	}
	if sys.Score <= med.Score {
		t.Errorf("SYSTEM (%d) should score higher than medium (%d) in auto-elevated mode", sys.Score, med.Score)
	}
}

func TestScoreProcessMonitoredPenalty(t *testing.T) {
	// svchost is monitored but not critical
	svchost := ProcessInfo{PID: 500, Name: "svchost.exe", Arch: "x64", User: "SYSTEM", IntegrityLevel: 4}
	result := scoreProcess(svchost, 1000, "x64", "testuser", 2, TargetAuto)
	if result == nil {
		t.Fatal("svchost should be scored (not excluded)")
	}

	// explorer should score higher than svchost
	explorer := ProcessInfo{PID: 600, Name: "explorer.exe", Arch: "x64", User: "testuser", IntegrityLevel: 2}
	explorerResult := scoreProcess(explorer, 1000, "x64", "testuser", 2, TargetAuto)
	if explorerResult == nil {
		t.Fatal("explorer should be scored")
	}
	if explorerResult.Score <= result.Score {
		t.Errorf("explorer (%d) should score higher than svchost (%d)", explorerResult.Score, result.Score)
	}
}

func TestBestTargetEmpty(t *testing.T) {
	_, err := BestTarget(nil)
	if err == nil {
		t.Error("should error on empty targets")
	}
	_, err = BestTarget([]InjectionTarget{})
	if err == nil {
		t.Error("should error on empty targets")
	}
}

func TestBestTargetReturnsFirst(t *testing.T) {
	targets := []InjectionTarget{
		{PID: 100, Score: 90},
		{PID: 200, Score: 50},
	}
	pid, err := BestTarget(targets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 100 {
		t.Errorf("expected PID 100, got %d", pid)
	}
}

func TestFormatTargetSelection(t *testing.T) {
	targets := []InjectionTarget{
		{PID: 100, Name: "explorer.exe", Score: 90, Reasons: []string{"arch match", "common process"}},
	}
	output := FormatTargetSelection(targets)
	if output == "" {
		t.Error("should produce output")
	}
	if len(output) < 10 {
		t.Error("output too short")
	}
}

func TestTargetModeValues(t *testing.T) {
	if TargetAuto != "auto" {
		t.Error("wrong TargetAuto value")
	}
	if TargetAutoElevated != "auto-elevated" {
		t.Error("wrong TargetAutoElevated value")
	}
	if TargetAutoUser != "auto-user" {
		t.Error("wrong TargetAutoUser value")
	}
}
