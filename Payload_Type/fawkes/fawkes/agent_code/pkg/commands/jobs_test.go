package commands

import (
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestJobsName(t *testing.T) {
	cmd := &JobsCommand{}
	if cmd.Name() != "jobs" {
		t.Errorf("Expected 'jobs', got '%s'", cmd.Name())
	}
}

func TestJobsDescription(t *testing.T) {
	cmd := &JobsCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestJobsNoRunningTasks(t *testing.T) {
	// Clear any tracked tasks
	runningTasks.Range(func(key, _ interface{}) bool {
		runningTasks.Delete(key)
		return true
	})

	cmd := &JobsCommand{}
	result := cmd.Execute(structs.Task{ID: "jobs-1", Params: ""})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "No running tasks") {
		t.Errorf("Expected 'No running tasks', got: %s", result.Output)
	}
}

func TestJobsWithRunningTasks(t *testing.T) {
	// Clear existing
	runningTasks.Range(func(key, _ interface{}) bool {
		runningTasks.Delete(key)
		return true
	})

	// Add some fake running tasks
	task1 := &structs.Task{
		ID:        "task-111",
		Command:   "portscan",
		StartTime: time.Now().Add(-30 * time.Second),
	}
	task2 := &structs.Task{
		ID:        "task-222",
		Command:   "find",
		StartTime: time.Now().Add(-10 * time.Second),
	}
	TrackTask(task1)
	TrackTask(task2)
	defer func() {
		UntrackTask("task-111")
		UntrackTask("task-222")
	}()

	cmd := &JobsCommand{}
	result := cmd.Execute(structs.Task{ID: "jobs-task", Params: ""})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "portscan") {
		t.Errorf("Expected 'portscan' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "find") {
		t.Errorf("Expected 'find' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "task-111") {
		t.Errorf("Expected task ID 'task-111' in output, got: %s", result.Output)
	}
	// Header should be present
	if !strings.Contains(result.Output, "Task ID") {
		t.Errorf("Expected header row, got: %s", result.Output)
	}
}

func TestJobsSkipsSelf(t *testing.T) {
	// Clear existing
	runningTasks.Range(func(key, _ interface{}) bool {
		runningTasks.Delete(key)
		return true
	})

	// Track only the jobs command itself
	self := &structs.Task{
		ID:        "self-task",
		Command:   "jobs",
		StartTime: time.Now(),
	}
	TrackTask(self)
	defer UntrackTask("self-task")

	cmd := &JobsCommand{}
	result := cmd.Execute(structs.Task{ID: "self-task", Params: ""})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	// Should report only self running
	if !strings.Contains(result.Output, "No running tasks (only this jobs command)") {
		t.Errorf("Expected only-self message, got: %s", result.Output)
	}
}

func TestJobsSortsbyStartTime(t *testing.T) {
	runningTasks.Range(func(key, _ interface{}) bool {
		runningTasks.Delete(key)
		return true
	})

	// Add tasks with specific ordering
	older := &structs.Task{
		ID:        "task-old",
		Command:   "ping",
		StartTime: time.Now().Add(-60 * time.Second),
	}
	newer := &structs.Task{
		ID:        "task-new",
		Command:   "du",
		StartTime: time.Now().Add(-5 * time.Second),
	}
	TrackTask(newer) // add newer first
	TrackTask(older)
	defer func() {
		UntrackTask("task-old")
		UntrackTask("task-new")
	}()

	cmd := &JobsCommand{}
	result := cmd.Execute(structs.Task{ID: "jobs-sort", Params: ""})

	// "ping" (older) should appear before "du" (newer)
	pingIdx := strings.Index(result.Output, "ping")
	duIdx := strings.Index(result.Output, "du")
	if pingIdx < 0 || duIdx < 0 {
		t.Fatalf("Expected both ping and du in output, got: %s", result.Output)
	}
	if pingIdx > duIdx {
		t.Errorf("Expected older task (ping) listed before newer (du)")
	}
}
