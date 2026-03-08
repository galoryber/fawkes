package commands

import (
	"encoding/json"
	"runtime"
	"testing"

	"fawkes/pkg/structs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunasCommand_Name(t *testing.T) {
	cmd := &RunasCommand{}
	assert.Equal(t, "runas", cmd.Name())
}

func TestRunasCommand_Description(t *testing.T) {
	cmd := &RunasCommand{}
	assert.NotEmpty(t, cmd.Description())
}

func TestRunasArgs_Unmarshal(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected runasArgs
	}{
		{
			name: "full args",
			json: `{"command":"whoami","username":"testuser","password":"pass123","domain":"CORP","netonly":true}`,
			expected: runasArgs{
				Command:  "whoami",
				Username: "testuser",
				Password: "pass123",
				Domain:   "CORP",
				NetOnly:  true,
			},
		},
		{
			name: "minimal args",
			json: `{"command":"id","username":"nobody"}`,
			expected: runasArgs{
				Command:  "id",
				Username: "nobody",
			},
		},
		{
			name: "empty",
			json: `{}`,
			expected: runasArgs{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args runasArgs
			err := json.Unmarshal([]byte(tt.json), &args)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, args)
		})
	}
}

func TestRunasCommand_InvalidJSON(t *testing.T) {
	cmd := &RunasCommand{}
	task := structs.Task{Params: "not-json"}
	result := cmd.Execute(task)
	assert.Equal(t, "error", result.Status)
	assert.True(t, result.Completed)
	assert.Contains(t, result.Output, "Error parsing parameters")
}

func TestRunasCommand_MissingCommand(t *testing.T) {
	cmd := &RunasCommand{}
	task := structs.Task{Params: `{"username":"testuser","password":"pass"}`}
	result := cmd.Execute(task)
	assert.Equal(t, "error", result.Status)
	assert.Contains(t, result.Output, "required")
}

func TestRunasCommand_MissingUsername(t *testing.T) {
	cmd := &RunasCommand{}
	task := structs.Task{Params: `{"command":"whoami","password":"pass"}`}
	result := cmd.Execute(task)
	assert.Equal(t, "error", result.Status)
	assert.Contains(t, result.Output, "required")
}

func TestRunasCommand_NetOnly_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test")
	}
	cmd := &RunasCommand{}
	task := structs.Task{Params: `{"command":"whoami","username":"root","netonly":true}`}
	result := cmd.Execute(task)
	assert.Equal(t, "error", result.Status)
	assert.Contains(t, result.Output, "Windows-only")
}

func TestRunasCommand_NonexistentUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test")
	}
	cmd := &RunasCommand{}
	task := structs.Task{Params: `{"command":"whoami","username":"nonexistent_user_12345"}`}
	result := cmd.Execute(task)
	assert.Equal(t, "error", result.Status)
	assert.Contains(t, result.Output, "not found")
}

func TestRunasCommand_DomainBackslashStripping(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test — domain stripping")
	}
	cmd := &RunasCommand{}
	// Use a real user that exists on most Linux systems
	task := structs.Task{Params: `{"command":"echo test","username":"CORP\\root"}`}
	result := cmd.Execute(task)
	// Should attempt to run as "root" (stripped domain)
	// Will succeed if running as root, or fail with permissions error
	if result.Status == "success" {
		assert.Contains(t, result.Output, "root")
	} else {
		// Not running as root — should still have parsed the username correctly
		assert.NotContains(t, result.Output, "not found")
	}
}

func TestRunasCommand_UPNStripping(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test — UPN stripping")
	}
	cmd := &RunasCommand{}
	task := structs.Task{Params: `{"command":"echo test","username":"root@domain.local"}`}
	result := cmd.Execute(task)
	// Should attempt to run as "root" (stripped UPN domain)
	if result.Status == "success" {
		assert.Contains(t, result.Output, "root")
	} else {
		assert.NotContains(t, result.Output, "not found")
	}
}

func TestRunasCommand_RootExecution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test")
	}
	// This test only passes when running as root
	// It's a functional test, not a unit test — skip in CI unless root
	cmd := &RunasCommand{}
	task := structs.Task{Params: `{"command":"id -un","username":"nobody"}`}
	result := cmd.Execute(task)

	if result.Status == "success" {
		// Running as root — setuid worked
		assert.Contains(t, result.Output, "nobody")
		assert.Contains(t, result.Output, "setuid")
	}
	// If not root, the error message should be clear
	assert.True(t, result.Completed)
}
