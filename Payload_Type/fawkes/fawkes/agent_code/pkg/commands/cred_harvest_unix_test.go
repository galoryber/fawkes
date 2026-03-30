//go:build !windows

package commands

import (
	"testing"
)

func TestCredHarvestDispatchUnknownAction(t *testing.T) {
	result := credHarvestDispatch(credHarvestArgs{Action: "invalid"})
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestCredHarvestDispatchShadow(t *testing.T) {
	result := credHarvestDispatch(credHarvestArgs{Action: "shadow"})
	// Should succeed (may not find /etc/shadow if not root)
	assertSuccess(t, result)
	assertOutputContains(t, result, "System Credential Files")
}

func TestCredHarvestDispatchCloud(t *testing.T) {
	result := credHarvestDispatch(credHarvestArgs{Action: "cloud"})
	assertSuccess(t, result)
}

func TestCredHarvestDispatchConfigs(t *testing.T) {
	result := credHarvestDispatch(credHarvestArgs{Action: "configs"})
	assertSuccess(t, result)
}

func TestCredHarvestDispatchHistory(t *testing.T) {
	result := credHarvestDispatch(credHarvestArgs{Action: "history"})
	assertSuccess(t, result)
}

func TestCredHarvestDispatchAll(t *testing.T) {
	result := credHarvestDispatch(credHarvestArgs{Action: "all"})
	assertSuccess(t, result)
	assertOutputContains(t, result, "System Credential Files")
}

func TestCredHarvestShadowWithFilter(t *testing.T) {
	result := credHarvestDispatch(credHarvestArgs{Action: "shadow", User: "nonexistentuser12345"})
	assertSuccess(t, result)
}

