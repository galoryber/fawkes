package commands

import (
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

// TestCatCommand tests the cat command's file reading and parameter parsing.
func TestCatCommand(t *testing.T) {
	cmd := &CatCommand{}

	if cmd.Name() != "cat" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "cat")
	}

	t.Run("empty params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error status for empty params, got %q", result.Status)
		}
	})

	t.Run("read existing file", func(t *testing.T) {
		// Create a temp file
		tmp := t.TempDir()
		path := filepath.Join(tmp, "test.txt")
		if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
			t.Fatal(err)
		}
		task := structs.Task{Params: path}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if result.Output != "hello world" {
			t.Errorf("output = %q, want %q", result.Output, "hello world")
		}
	})

	t.Run("read nonexistent file", func(t *testing.T) {
		task := structs.Task{Params: "/nonexistent/file/path.txt"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent file, got %q", result.Status)
		}
	})

	t.Run("quoted path", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "test.txt")
		if err := os.WriteFile(path, []byte("quoted"), 0644); err != nil {
			t.Fatal(err)
		}
		task := structs.Task{Params: `"` + path + `"`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success with quoted path, got %q: %s", result.Status, result.Output)
		}
		if result.Output != "quoted" {
			t.Errorf("output = %q, want %q", result.Output, "quoted")
		}
	})
}

// TestMkdirCommand tests the mkdir command's directory creation and parameter parsing.
func TestMkdirCommand(t *testing.T) {
	cmd := &MkdirCommand{}

	if cmd.Name() != "mkdir" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "mkdir")
	}

	t.Run("empty params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty params, got %q", result.Status)
		}
	})

	t.Run("create directory with plain string", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "newdir")
		task := structs.Task{Params: path}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Error("directory was not created")
		}
	})

	t.Run("create directory with JSON params", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "jsondir")
		task := structs.Task{Params: `{"path":"` + path + `"}`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Error("directory was not created from JSON params")
		}
	})

	t.Run("create nested directory", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "a", "b", "c")
		task := structs.Task{Params: path}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success for nested mkdir, got %q: %s", result.Status, result.Output)
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Error("nested directory was not created")
		}
	})
}

// TestRmCommand tests the rm command's file/directory removal and parameter parsing.
func TestRmCommand(t *testing.T) {
	cmd := &RmCommand{}

	if cmd.Name() != "rm" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "rm")
	}

	t.Run("empty params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty params, got %q", result.Status)
		}
	})

	t.Run("remove file", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "todelete.txt")
		if err := os.WriteFile(path, []byte("delete me"), 0644); err != nil {
			t.Fatal(err)
		}
		task := structs.Task{Params: path}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("file was not removed")
		}
	})

	t.Run("remove directory", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "toremove")
		os.MkdirAll(path, 0755)
		os.WriteFile(filepath.Join(path, "child.txt"), []byte("x"), 0644)

		task := structs.Task{Params: path}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("directory was not removed")
		}
	})

	t.Run("remove nonexistent", func(t *testing.T) {
		task := structs.Task{Params: "/nonexistent/path/file.txt"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent path, got %q", result.Status)
		}
	})

	t.Run("remove with JSON params", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "jsonrm.txt")
		if err := os.WriteFile(path, []byte("delete"), 0644); err != nil {
			t.Fatal(err)
		}
		task := structs.Task{Params: `{"path":"` + path + `"}`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success with JSON, got %q: %s", result.Status, result.Output)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("file was not removed via JSON params")
		}
	})
}

// TestCdCommand tests the cd command's directory change and parameter parsing.
func TestCdCommand(t *testing.T) {
	cmd := &CdCommand{}

	if cmd.Name() != "cd" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "cd")
	}

	// Save and restore CWD
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	t.Run("empty params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty params, got %q", result.Status)
		}
	})

	t.Run("change to temp dir", func(t *testing.T) {
		tmp := t.TempDir()
		task := structs.Task{Params: tmp}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
	})

	t.Run("change with JSON params", func(t *testing.T) {
		tmp := t.TempDir()
		task := structs.Task{Params: `{"path":"` + tmp + `"}`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success with JSON, got %q: %s", result.Status, result.Output)
		}
	})

	t.Run("nonexistent directory", func(t *testing.T) {
		task := structs.Task{Params: "/nonexistent/directory/path"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent dir, got %q", result.Status)
		}
	})
}

// TestPwdCommand tests the pwd command.
func TestPwdCommand(t *testing.T) {
	cmd := &PwdCommand{}

	if cmd.Name() != "pwd" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "pwd")
	}

	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if result.Output == "" {
		t.Error("expected non-empty output from pwd")
	}
}

// TestLsCommand tests the ls command's directory listing.
func TestLsCommand(t *testing.T) {
	cmd := &LsCommand{}

	if cmd.Name() != "ls" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "ls")
	}

	t.Run("list current directory", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
	})

	t.Run("list temp directory", func(t *testing.T) {
		tmp := t.TempDir()
		os.WriteFile(filepath.Join(tmp, "file1.txt"), []byte("a"), 0644)
		os.WriteFile(filepath.Join(tmp, "file2.txt"), []byte("b"), 0644)
		os.Mkdir(filepath.Join(tmp, "subdir"), 0755)

		task := structs.Task{Params: tmp}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
	})

	t.Run("list with JSON params", func(t *testing.T) {
		tmp := t.TempDir()
		task := structs.Task{Params: `{"path":"` + tmp + `"}`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success with JSON, got %q: %s", result.Status, result.Output)
		}
	})
}

// TestEnvCommand tests the env command.
func TestEnvCommand(t *testing.T) {
	cmd := &EnvCommand{}

	if cmd.Name() != "env" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "env")
	}

	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if result.Output == "" {
		t.Error("expected non-empty env output")
	}
}

// TestCpCommand tests the cp command's file copy and parameter parsing.
func TestCpCommand(t *testing.T) {
	cmd := &CpCommand{}

	if cmd.Name() != "cp" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "cp")
	}

	t.Run("copy file with JSON params", func(t *testing.T) {
		tmp := t.TempDir()
		src := filepath.Join(tmp, "src.txt")
		dst := filepath.Join(tmp, "dst.txt")
		os.WriteFile(src, []byte("copy me"), 0644)

		task := structs.Task{Params: `{"source":"` + src + `","destination":"` + dst + `"}`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		data, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("failed to read destination: %v", err)
		}
		if string(data) != "copy me" {
			t.Errorf("copied content = %q, want %q", string(data), "copy me")
		}
	})

	t.Run("missing source", func(t *testing.T) {
		tmp := t.TempDir()
		task := structs.Task{Params: `{"source":"/nonexistent/file.txt","destination":"` + filepath.Join(tmp, "dst.txt") + `"}`}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for missing source, got %q", result.Status)
		}
	})

	t.Run("non-JSON params returns error", func(t *testing.T) {
		task := structs.Task{Params: "not json at all"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for non-JSON cp params, got %q", result.Status)
		}
	})
}

// TestMvCommand tests the mv command.
func TestMvCommand(t *testing.T) {
	cmd := &MvCommand{}

	if cmd.Name() != "mv" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "mv")
	}

	t.Run("move file with JSON params", func(t *testing.T) {
		tmp := t.TempDir()
		src := filepath.Join(tmp, "src.txt")
		dst := filepath.Join(tmp, "dst.txt")
		os.WriteFile(src, []byte("move me"), 0644)

		task := structs.Task{Params: `{"source":"` + src + `","destination":"` + dst + `"}`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if _, err := os.Stat(src); !os.IsNotExist(err) {
			t.Error("source still exists after move")
		}
		data, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("failed to read destination: %v", err)
		}
		if string(data) != "move me" {
			t.Errorf("moved content = %q, want %q", string(data), "move me")
		}
	})
}

// TestPsCommand tests the ps command.
func TestPsCommand(t *testing.T) {
	cmd := &PsCommand{}

	if cmd.Name() != "ps" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "ps")
	}

	t.Run("list all processes", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if result.Output == "" {
			t.Error("expected non-empty process list")
		}
	})
}

// TestSetenvCommand tests the setenv command.
func TestSetenvCommand(t *testing.T) {
	cmd := &SetenvCommand{}

	if cmd.Name() != "setenv" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "setenv")
	}

	t.Run("set variable via JSON", func(t *testing.T) {
		task := structs.Task{Params: `{"action":"set","name":"FAWKES_TEST_VAR","value":"hello123"}`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if val := os.Getenv("FAWKES_TEST_VAR"); val != "hello123" {
			t.Errorf("env var = %q, want %q", val, "hello123")
		}
	})

	t.Run("unset variable via JSON", func(t *testing.T) {
		os.Setenv("FAWKES_TEST_VAR2", "toremove")
		task := structs.Task{Params: `{"action":"unset","name":"FAWKES_TEST_VAR2"}`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if val, exists := os.LookupEnv("FAWKES_TEST_VAR2"); exists {
			t.Errorf("env var still set: %q", val)
		}
	})

	t.Run("set variable with manual syntax", func(t *testing.T) {
		task := structs.Task{Params: `set FAWKES_MANUAL=world456`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if val := os.Getenv("FAWKES_MANUAL"); val != "world456" {
			t.Errorf("env var = %q, want %q", val, "world456")
		}
		os.Unsetenv("FAWKES_MANUAL")
	})

	t.Run("unset variable with manual syntax", func(t *testing.T) {
		os.Setenv("FAWKES_MANUAL2", "bye")
		task := structs.Task{Params: `unset FAWKES_MANUAL2`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if _, exists := os.LookupEnv("FAWKES_MANUAL2"); exists {
			t.Error("env var still set after unset")
		}
	})

	t.Run("empty name", func(t *testing.T) {
		task := structs.Task{Params: `{"action":"set","name":"","value":"x"}`}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty name, got %q", result.Status)
		}
	})

	t.Run("unknown action", func(t *testing.T) {
		task := structs.Task{Params: `{"action":"delete","name":"FOO"}`}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for unknown action, got %q", result.Status)
		}
	})

	t.Run("set with empty value", func(t *testing.T) {
		task := structs.Task{Params: `{"action":"set","name":"FAWKES_EMPTY","value":""}`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if val, exists := os.LookupEnv("FAWKES_EMPTY"); !exists || val != "" {
			t.Errorf("env var should exist with empty value, got exists=%v val=%q", exists, val)
		}
		os.Unsetenv("FAWKES_EMPTY")
	})

	t.Run("manual set without equals sign", func(t *testing.T) {
		task := structs.Task{Params: `set NOEQUALS`}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for missing =, got %q", result.Status)
		}
	})

	// Cleanup
	os.Unsetenv("FAWKES_TEST_VAR")
}
