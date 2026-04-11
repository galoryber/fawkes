package agentfunctions

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// buildCommandConfig holds parameters needed to construct the Go build command.
type buildCommandConfig struct {
	targetOs      string
	goarch        string
	mode          string
	garble        bool
	c2ProfileName string
	payloadUUID   string
	macOSVersion  string
	ldflags       string
	buildParams   agentstructs.BuildParameters
}

// buildCommandResult holds the output of constructBuildCommand.
type buildCommandResult struct {
	command     string
	payloadName string
}

// constructBuildCommand builds the Go/Garble compile command string and output filename.
func constructBuildCommand(cfg buildCommandConfig) buildCommandResult {
	goarch := cfg.goarch
	tags := cfg.c2ProfileName
	// Clear both Go and Garble build caches to ensure embedded files (padding.bin)
	// are re-read from disk. Garble has its own cache (~/.cache/garble) separate
	// from GOCACHE — without clearing it, Garble reuses stale cached objects
	// even when the underlying embedded file has changed.
	command := fmt.Sprintf("rm -rf /deps; go clean -cache 2>/dev/null; rm -rf \"${HOME}/.cache/garble\" 2>/dev/null; CGO_ENABLED=0 GOOS=%s GOARCH=%s ", cfg.targetOs, goarch)
	buildmodeflag := "default"
	if cfg.mode == "shared" || cfg.mode == "windows-shellcode" {
		buildmodeflag = "c-shared"
		tags += ",shared" // Add shared tag to include exports.go
		command = strings.Replace(command, "CGO_ENABLED=0", "CGO_ENABLED=1", 1)
		// Add extended DLL exports (regsvr32, ServiceMain, COM) when requested
		if dllExports, err := cfg.buildParams.GetStringArg("dll_exports"); err == nil && dllExports == "full" {
			tags += ",dllexports"
		}
	}
	goCmd := fmt.Sprintf("-trimpath -tags %s -buildmode %s -ldflags \"%s\"", tags, buildmodeflag, cfg.ldflags)
	if cfg.mode == "shared" || cfg.mode == "windows-shellcode" {
		if cfg.targetOs == "darwin" {
			command += "CC=o64-clang CXX=o64-clang++ "
		} else if cfg.targetOs == "windows" {
			command += "CC=x86_64-w64-mingw32-gcc "
		} else {
			if goarch == "arm64" {
				command += "CC=aarch64-linux-gnu-gcc "
			}
		}
	}
	// Enable CGO for Windows builds (needed for go-coff BOF execution)
	if cfg.targetOs == "windows" && cfg.mode != "shared" {
		command = strings.Replace(command, "CGO_ENABLED=0", "CGO_ENABLED=1", 1)
		if goarch == "amd64" {
			command += "CC=x86_64-w64-mingw32-gcc "
		} else if goarch == "386" {
			command += "CC=i686-w64-mingw32-gcc "
		}
	}
	// GOGARBLE scopes which packages garble obfuscates. Using "fawkes" restricts
	// obfuscation to our agent code only, avoiding OOM on large dependency files
	// (e.g., go-msrpc/win32_errors.go has ~2700 string literals that exhaust RAM
	// when -literals tries to obfuscate them all with GOGARBLE=*).
	command += "GOGARBLE=fawkes "
	if cfg.garble {
		command += "/go/bin/garble -tiny -literals -seed random build "
	} else {
		command += "go build "
	}
	payloadName := fmt.Sprintf("%s-%s", cfg.payloadUUID, cfg.targetOs)
	if cfg.targetOs == "darwin" {
		payloadName += fmt.Sprintf("-%s", cfg.macOSVersion)
	}
	payloadName += fmt.Sprintf("-%s", goarch)

	// Add file extension based on mode before constructing the build command
	if cfg.mode == "shared" {
		if cfg.targetOs == "windows" {
			payloadName += ".dll"
		} else if cfg.targetOs == "darwin" {
			payloadName += ".dylib"
		} else {
			payloadName += ".so"
		}
	} else if cfg.mode == "windows-shellcode" {
		payloadName += ".dll"
		// Build as DLL first, then convert to shellcode via Merlin's sRDI
	}

	command += fmt.Sprintf("%s -o /build/%s .", goCmd, payloadName)

	return buildCommandResult{command: command, payloadName: payloadName}
}

// compileResult holds the output from running the Go compiler.
type compileResult struct {
	stdout string
	stderr string
}

// executeCompilation runs the build command and reports the result to Mythic.
// Returns the compile result and an error if compilation failed.
func executeCompilation(command, payloadUUID string, garble bool) (compileResult, error) {
	// Report configuring step
	fmt.Println("build command : " + command)

	cmd := exec.Command("/bin/bash")
	cmd.Stdin = strings.NewReader(command)
	cmd.Dir = "./fawkes/agent_code/"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
			PayloadUUID: payloadUUID,
			StepName:    "Compiling",
			StepSuccess: false,
			StepStdout:  fmt.Sprintf("failed to compile\n%s\n%s\n%s", stderr.String(), stdout.String(), err.Error()),
		})
		return compileResult{stdout: stdout.String(), stderr: stderr.String() + "\n" + err.Error()}, err
	}

	outputString := stdout.String()
	if !garble {
		outputString += "\n" + stderr.String()
	}
	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
		PayloadUUID: payloadUUID,
		StepName:    "Compiling",
		StepSuccess: true,
		StepStdout:  fmt.Sprintf("Successfully executed\n%s", outputString),
	})

	return compileResult{stdout: stdout.String(), stderr: stderr.String()}, nil
}

// collectPayloadOutput reads the built binary, applies shellcode conversion if needed,
// and populates the build response with the final payload and filename.
func collectPayloadOutput(resp *agentstructs.PayloadBuildResponse, payloadName, mode, targetOs, payloadUUID string) {
	payloadBytes, err := os.ReadFile(fmt.Sprintf("/build/%s", payloadName))
	if err != nil {
		resp.Success = false
		resp.BuildMessage = "Failed to find final payload"
		return
	}

	if mode == "windows-shellcode" {
		// Convert DLL to shellcode using sRDI
		// Use "Run" function and clearHeader=true to match Merlin configuration
		shellcode, err := convertDllToShellcode(payloadBytes, "Run", true)
		if err != nil {
			resp.Success = false
			resp.BuildMessage = fmt.Sprintf("Failed to convert DLL to shellcode: %v", err)
			resp.BuildStdErr += fmt.Sprintf("\nShellcode conversion error: %v", err)
			return
		}
		resp.Payload = &shellcode
		resp.Success = true
		resp.BuildMessage = "Successfully built shellcode payload!"
		extension := "bin"
		filename := fmt.Sprintf("fawkes.%s", extension)
		resp.UpdatedFilename = &filename
		// Track shellcode artifact in Mythic file vault
		mythicrpc.SendMythicRPCFileCreate(mythicrpc.MythicRPCFileCreateMessage{
			PayloadUUID:  payloadUUID,
			FileContents: shellcode,
			Filename:     filename,
			Comment:      fmt.Sprintf("sRDI shellcode — OS: %s, Mode: %s, DLL size: %d, Shellcode size: %d", targetOs, mode, len(payloadBytes), len(shellcode)),
		})
		return
	}

	resp.Payload = &payloadBytes
	resp.Success = true
	resp.BuildMessage = "Successfully built payload!"
	extension := payloadFileExtension(mode, targetOs)
	filename := fmt.Sprintf("fawkes.%s", extension)
	resp.UpdatedFilename = &filename
	// Track payload artifact in Mythic file vault
	mythicrpc.SendMythicRPCFileCreate(mythicrpc.MythicRPCFileCreateMessage{
		PayloadUUID:  payloadUUID,
		FileContents: payloadBytes,
		Filename:     filename,
		Comment:      fmt.Sprintf("Payload — OS: %s, Mode: %s, Size: %d bytes", targetOs, mode, len(payloadBytes)),
	})
}

// payloadFileExtension returns the file extension for the given build mode and OS.
func payloadFileExtension(mode, targetOs string) string {
	if mode == "shared" {
		switch targetOs {
		case "windows":
			return "dll"
		case "darwin":
			return "dylib"
		default:
			return "so"
		}
	}
	// default-executable mode
	if targetOs == "windows" {
		return "exe"
	}
	return "bin"
}
