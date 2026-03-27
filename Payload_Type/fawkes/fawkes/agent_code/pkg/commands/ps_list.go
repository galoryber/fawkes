//go:build !windows

package commands

import (
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

func getProcessList(args PsArgs) ([]ProcessInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo
	filterLower := strings.ToLower(args.Filter)
	userFilterLower := strings.ToLower(args.User)

	for _, p := range procs {
		if args.PID > 0 && p.Pid != args.PID {
			continue
		}

		name, err := p.Name()
		if err != nil {
			continue
		}

		if args.Filter != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}

		ppid, _ := p.Ppid()
		if args.PPID > 0 && ppid != args.PPID {
			continue
		}

		username, _ := p.Username()
		if args.User != "" && !strings.Contains(strings.ToLower(username), userFilterLower) {
			continue
		}

		cmdline, _ := p.Cmdline()
		exe, _ := p.Exe()

		processes = append(processes, ProcessInfo{
			PID:     p.Pid,
			PPID:    ppid,
			Name:    name,
			Arch:    runtime.GOARCH,
			User:    username,
			BinPath: exe,
			CmdLine: cmdline,
		})
	}

	return processes, nil
}
