//go:build linux

package commands

import (
	"testing"
)

func TestCheckYamaScope(t *testing.T) {
	scope, hint := checkYamaScope()
	if scope < -1 || scope > 3 {
		t.Errorf("unexpected ptrace_scope value: %d", scope)
	}
	switch scope {
	case -1:
		if hint == "" {
			t.Error("scope -1 should have a hint message")
		}
		t.Logf("Yama not loaded: %s", hint)
	case 0:
		if hint != "" {
			t.Errorf("scope 0 should have empty hint, got: %s", hint)
		}
		t.Log("Yama scope=0 (classic)")
	case 1:
		if hint == "" {
			t.Error("scope 1 should have a hint message")
		}
		t.Logf("Yama scope=1 (restricted): %s", hint)
	case 2:
		if hint == "" {
			t.Error("scope 2 should have a hint message")
		}
		t.Logf("Yama scope=2 (admin-only): %s", hint)
	case 3:
		if hint == "" {
			t.Error("scope 3 should have a hint message")
		}
		t.Logf("Yama scope=3 (disabled): %s", hint)
	}
}

func TestCheckYamaScopeMessages(t *testing.T) {
	scope, hint := checkYamaScope()
	if scope >= 1 {
		if hint == "" {
			t.Error("non-zero scope should provide actionable hint")
		}
	}
	t.Logf("scope=%d hint=%q", scope, hint)
}
