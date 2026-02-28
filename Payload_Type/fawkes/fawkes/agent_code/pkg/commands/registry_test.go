package commands

import (
	"testing"

	"fawkes/pkg/structs"
)

// registryTestCommand is a minimal Command implementation for registry tests.
type registryTestCommand struct {
	name string
}

func (m *registryTestCommand) Name() string        { return m.name }
func (m *registryTestCommand) Description() string { return "registry test command" }
func (m *registryTestCommand) Execute(task structs.Task) structs.CommandResult {
	return structs.CommandResult{Output: "ok", Status: "success", Completed: true}
}

func TestRegisterCommandAndRetrieve(t *testing.T) {
	mock := &registryTestCommand{name: "reg-test-register"}
	RegisterCommand(mock)
	defer func() {
		// Clean up: remove from registry
		registryMutex.Lock()
		delete(commandRegistry, "reg-test-register")
		registryMutex.Unlock()
	}()

	retrieved := GetCommand("reg-test-register")
	if retrieved == nil {
		t.Fatal("GetCommand returned nil for registered command")
	}
	if retrieved.Name() != "reg-test-register" {
		t.Errorf("Name() = %q, want %q", retrieved.Name(), "reg-test-register")
	}
}

func TestGetCommandNotFound(t *testing.T) {
	cmd := GetCommand("completely-nonexistent-command-12345")
	if cmd != nil {
		t.Errorf("expected nil for nonexistent command, got %v", cmd)
	}
}

func TestGetAllCommandsMultiple(t *testing.T) {
	// Register a few test commands
	names := []string{"reg-test-a", "reg-test-b", "reg-test-c"}
	for _, n := range names {
		RegisterCommand(&registryTestCommand{name: n})
	}
	defer func() {
		registryMutex.Lock()
		for _, n := range names {
			delete(commandRegistry, n)
		}
		registryMutex.Unlock()
	}()

	all := GetAllCommands()
	for _, n := range names {
		if _, ok := all[n]; !ok {
			t.Errorf("GetAllCommands missing registered command %q", n)
		}
	}
}

func TestTrackTask(t *testing.T) {
	task := structs.NewTask("track-test-1", "test", "")
	TrackTask(&task)
	defer UntrackTask("track-test-1")

	retrieved, ok := GetRunningTask("track-test-1")
	if !ok {
		t.Fatal("expected GetRunningTask to find tracked task")
	}
	if retrieved.ID != "track-test-1" {
		t.Errorf("expected task ID 'track-test-1', got %q", retrieved.ID)
	}
}

func TestUntrackTask(t *testing.T) {
	task := structs.NewTask("track-test-2", "test", "")
	TrackTask(&task)
	UntrackTask("track-test-2")

	_, ok := GetRunningTask("track-test-2")
	if ok {
		t.Error("expected GetRunningTask to return false after UntrackTask")
	}
}

func TestGetRunningTasks(t *testing.T) {
	// Clean up any leftover tasks from other tests
	task1 := structs.NewTask("running-test-1", "cmd1", "")
	task2 := structs.NewTask("running-test-2", "cmd2", "")
	TrackTask(&task1)
	TrackTask(&task2)
	defer func() {
		UntrackTask("running-test-1")
		UntrackTask("running-test-2")
	}()

	running := GetRunningTasks()
	if _, ok := running["running-test-1"]; !ok {
		t.Error("expected running-test-1 in GetRunningTasks")
	}
	if _, ok := running["running-test-2"]; !ok {
		t.Error("expected running-test-2 in GetRunningTasks")
	}
}

func TestGetRunningTaskByID(t *testing.T) {
	task := structs.NewTask("running-specific-1", "test", "")
	TrackTask(&task)
	defer UntrackTask("running-specific-1")

	retrieved, ok := GetRunningTask("running-specific-1")
	if !ok {
		t.Fatal("expected to find running task by ID")
	}
	if retrieved.Command != "test" {
		t.Errorf("expected Command 'test', got %q", retrieved.Command)
	}
}

func TestGetRunningTaskNotFound(t *testing.T) {
	_, ok := GetRunningTask("does-not-exist-99999")
	if ok {
		t.Error("expected GetRunningTask to return false for nonexistent task")
	}
}
