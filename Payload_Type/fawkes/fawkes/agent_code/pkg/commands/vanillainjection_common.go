package commands

import "strings"

type VanillaInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
	Action       string `json:"action"`
	Target       string `json:"target"`
}

func isMigrateAction(action string) bool {
	return strings.EqualFold(action, "migrate")
}
