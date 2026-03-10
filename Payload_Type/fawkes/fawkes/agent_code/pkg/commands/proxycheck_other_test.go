//go:build !windows

package commands

import (
	"runtime"
	"testing"
)

func TestProxyCheckPlatform(t *testing.T) {
	result := proxyCheckPlatform()
	switch runtime.GOOS {
	case "linux":
		// On Linux, should check system proxy files
		if result == "" {
			t.Log("proxyCheckPlatform returned empty (no proxy config found — expected)")
		}
	case "darwin":
		// On macOS, should check system preferences
		if result == "" {
			t.Log("proxyCheckPlatform returned empty (no proxy config found — expected)")
		}
	default:
		// On other platforms, should return empty
		if result != "" {
			t.Errorf("expected empty for %s, got: %s", runtime.GOOS, result)
		}
	}
}
