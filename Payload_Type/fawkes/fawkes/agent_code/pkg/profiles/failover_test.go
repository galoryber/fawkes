package profiles

import (
	"errors"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

// mockProfile implements Profile for testing.
type mockProfile struct {
	uuid         string
	checkinErr   error
	taskingErr   error
	checkinCalls int
	taskingCalls int
}

func (m *mockProfile) Checkin(_ *structs.Agent) error {
	m.checkinCalls++
	return m.checkinErr
}

func (m *mockProfile) GetTasking(_ *structs.Agent, socks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error) {
	m.taskingCalls++
	return nil, nil, m.taskingErr
}

func (m *mockProfile) PostResponse(_ structs.Response, _ *structs.Agent, _ []structs.SocksMsg) ([]byte, error) {
	return nil, nil
}

func (m *mockProfile) GetCallbackUUID() string {
	return m.uuid
}

func TestFailoverManager_CheckinPrimarySucceeds(t *testing.T) {
	primary := &mockProfile{uuid: "uuid-primary"}
	backup := &mockProfile{uuid: "uuid-backup"}

	fm := NewFailoverManager([]Profile{primary, backup}, []string{"http", "discord"}, 3, 60)
	if err := fm.Checkin(&structs.Agent{}); err != nil {
		t.Fatalf("expected checkin success, got: %v", err)
	}
	if fm.CurrentIndex() != 0 {
		t.Errorf("expected primary (index 0), got %d", fm.CurrentIndex())
	}
	if fm.GetCallbackUUID() != "uuid-primary" {
		t.Errorf("expected primary UUID, got %q", fm.GetCallbackUUID())
	}
}

func TestFailoverManager_CheckinFallsBackToSecondary(t *testing.T) {
	primary := &mockProfile{uuid: "uuid-primary", checkinErr: errors.New("primary down")}
	backup := &mockProfile{uuid: "uuid-backup"}

	fm := NewFailoverManager([]Profile{primary, backup}, []string{"http", "discord"}, 3, 60)
	if err := fm.Checkin(&structs.Agent{}); err != nil {
		t.Fatalf("expected checkin success via backup, got: %v", err)
	}
	if fm.CurrentIndex() != 1 {
		t.Errorf("expected backup (index 1), got %d", fm.CurrentIndex())
	}
	if fm.GetCallbackUUID() != "uuid-backup" {
		t.Errorf("expected backup UUID, got %q", fm.GetCallbackUUID())
	}
}

func TestFailoverManager_CheckinAllFail(t *testing.T) {
	primary := &mockProfile{checkinErr: errors.New("primary down")}
	backup := &mockProfile{checkinErr: errors.New("backup down")}

	fm := NewFailoverManager([]Profile{primary, backup}, []string{"http", "discord"}, 3, 60)
	if err := fm.Checkin(&structs.Agent{}); err == nil {
		t.Fatal("expected checkin failure when all profiles fail")
	}
}

func TestFailoverManager_RotatesAfterThreshold(t *testing.T) {
	primary := &mockProfile{uuid: "uuid-primary", taskingErr: errors.New("primary unreachable")}
	backup := &mockProfile{uuid: "uuid-backup"}

	fm := NewFailoverManager([]Profile{primary, backup}, []string{"http", "discord"}, 3, 60)
	// Manually set primary as current (simulating successful checkin)
	fm.current = 0

	agent := &structs.Agent{}
	// First 2 failures: stays on primary
	for i := 0; i < 2; i++ {
		_, _, err := fm.GetTasking(agent, nil)
		if err == nil {
			t.Fatal("expected error from primary")
		}
		if fm.CurrentIndex() != 0 {
			t.Errorf("iteration %d: expected still on primary", i)
		}
	}
	// 3rd failure triggers rotation (backup checkin succeeds)
	_, _, err := fm.GetTasking(agent, nil)
	if err == nil {
		t.Fatal("expected error on rotation attempt")
	}
	if fm.CurrentIndex() != 1 {
		t.Errorf("expected switched to backup (index 1), got %d", fm.CurrentIndex())
	}
}

func TestFailoverManager_ResetsFailureOnSuccess(t *testing.T) {
	primary := &mockProfile{uuid: "uuid-primary"}

	fm := NewFailoverManager([]Profile{primary}, []string{"http"}, 3, 60)
	fm.current = 0
	fm.failures = 2

	_, _, err := fm.GetTasking(&structs.Agent{}, nil)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if fm.FailureCount() != 0 {
		t.Errorf("expected failures reset to 0, got %d", fm.FailureCount())
	}
}

func TestFailoverManager_RecoveryReturnsToPrimary(t *testing.T) {
	primary := &mockProfile{uuid: "uuid-primary"}
	backup := &mockProfile{uuid: "uuid-backup", taskingErr: errors.New("backup poll err")}

	// Short recovery period for the test
	fm := NewFailoverManager([]Profile{primary, backup}, []string{"http", "discord"}, 3, 1)
	fm.current = 1 // Simulate being on backup
	fm.lastRecovery = time.Now().Add(-2 * time.Second) // Recovery period elapsed

	// GetTasking should trigger recovery attempt (primary checkin succeeds) before polling backup
	_, _, _ = fm.GetTasking(&structs.Agent{}, nil)

	if fm.CurrentIndex() != 0 {
		t.Errorf("expected recovered to primary (index 0), got %d", fm.CurrentIndex())
	}
}

func TestFailoverManager_NoRecoveryBeforePeriodElapsed(t *testing.T) {
	primary := &mockProfile{uuid: "uuid-primary"}
	backup := &mockProfile{uuid: "uuid-backup"}

	fm := NewFailoverManager([]Profile{primary, backup}, []string{"http", "discord"}, 3, 300)
	fm.current = 1 // On backup
	fm.lastRecovery = time.Now() // Just attempted recovery

	fm.GetTasking(&structs.Agent{}, nil)

	// Primary checkin should NOT have been called (recovery period not elapsed)
	if primary.checkinCalls != 0 {
		t.Errorf("expected no recovery checkin, got %d calls", primary.checkinCalls)
	}
}

func TestFailoverManager_SingleProfileNoRotation(t *testing.T) {
	primary := &mockProfile{taskingErr: errors.New("always fails")}

	fm := NewFailoverManager([]Profile{primary}, []string{"http"}, 2, 60)
	fm.current = 0

	agent := &structs.Agent{}
	for i := 0; i < 5; i++ {
		fm.GetTasking(agent, nil)
	}
	// Should stay at index 0 — no other profiles to rotate to
	if fm.CurrentIndex() != 0 {
		t.Errorf("single-profile manager should stay at index 0, got %d", fm.CurrentIndex())
	}
}

func TestNewFailoverManager_DefaultsApplied(t *testing.T) {
	primary := &mockProfile{}
	fm := NewFailoverManager([]Profile{primary}, []string{"http"}, 0, 0)
	if fm.maxFailures != defaultFailoverThreshold {
		t.Errorf("expected default maxFailures %d, got %d", defaultFailoverThreshold, fm.maxFailures)
	}
	if fm.recoveryPeriod != time.Duration(defaultRecoverySeconds)*time.Second {
		t.Errorf("expected default recovery %v, got %v", time.Duration(defaultRecoverySeconds)*time.Second, fm.recoveryPeriod)
	}
}
