package commands

import "strings"

type VanillaInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
	Action       string `json:"action"`
	Target       string `json:"target"`
	SpawnTarget  string `json:"spawn_target"`
	StackSpoof   bool   `json:"stack_spoof"`
}

func isMigrateAction(action string) bool {
	return strings.EqualFold(action, "migrate")
}
