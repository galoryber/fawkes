package agentfunctions

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// buildMu serializes agent builds to prevent concurrent builds from interfering
// with each other's padding.bin file. Each build writes custom padding data to
// a shared file path before compiling, so overlapping builds would corrupt each
// other's embedded padding.
var buildMu sync.Mutex

func build(payloadBuildMsg agentstructs.PayloadBuildMessage) agentstructs.PayloadBuildResponse {
	payloadBuildResponse := agentstructs.PayloadBuildResponse{
		PayloadUUID:        payloadBuildMsg.PayloadUUID,
		Success:            true,
		UpdatedCommandList: &payloadBuildMsg.CommandList,
	}

	if len(payloadBuildMsg.C2Profiles) > 1 || len(payloadBuildMsg.C2Profiles) == 0 {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = "Failed to build - must select only one C2 Profile at a time"
		return payloadBuildResponse
	}
	macOSVersion := "10.12"
	targetOs := "linux"
	if payloadBuildMsg.SelectedOS == "macOS" {
		targetOs = "darwin"
	} else if payloadBuildMsg.SelectedOS == "Windows" {
		targetOs = "windows"
	}
	// Build Go linker flags (-ldflags) from C2 profile and build parameters.
	// This sets compile-time variables via -X flags for C2 config, opsec options, etc.
	fawkes_main_package := "main"
	ldflags, ldflagsErr := buildConfigLdflags(payloadBuildMsg, fawkes_main_package)
	if ldflagsErr != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = ldflagsErr.Error()
		return payloadBuildResponse
	}

	architecture, err := payloadBuildMsg.BuildParameters.GetStringArg("architecture")
	if err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = err.Error()
		return payloadBuildResponse
	}
	mode, err := payloadBuildMsg.BuildParameters.GetStringArg("mode")
	if err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = err.Error()
		return payloadBuildResponse
	}
	garble, err := payloadBuildMsg.BuildParameters.GetBooleanArg("garble")
	if err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = err.Error()
		return payloadBuildResponse
	}
	// Validate mode for target OS
	if mode == "windows-shellcode" && targetOs != "windows" {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = "windows-shellcode mode is only supported for Windows targets"
		return payloadBuildResponse
	}
	if mode == "windows-ps-stager" && targetOs != "windows" {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = "windows-ps-stager mode is only supported for Windows targets"
		return payloadBuildResponse
	}

	// Handle PowerShell stager mode early — no Go build needed
	if mode == "windows-ps-stager" {
		return buildPowerShellStager(payloadBuildMsg, &payloadBuildResponse)
	}
	// Add debug flag
	ldflags += fmt.Sprintf(" -X '%s.debug=%s'", fawkes_main_package, "false")
	ldflags += " -buildid="

	// Serialize builds: padding.bin is a shared file that must not be modified
	// by concurrent goroutines between the write and the go build invocation.
	buildMu.Lock()
	defer buildMu.Unlock()

	// Handle binary inflation (padding)
	inflateBytes, inflBytesErr := payloadBuildMsg.BuildParameters.GetStringArg("inflate_bytes")
	inflateCount, inflCountErr := payloadBuildMsg.BuildParameters.GetStringArg("inflate_count")
	if inflBytesErr != nil {
		fmt.Printf("[builder] Warning: could not read inflate_bytes parameter: %v\n", inflBytesErr)
	}
	if inflCountErr != nil {
		fmt.Printf("[builder] Warning: could not read inflate_count parameter: %v\n", inflCountErr)
	}
	paddingFile := "./fawkes/agent_code/padding.bin"
	fmt.Printf("[builder] inflate_bytes='%s' inflate_count='%s'\n", inflateBytes, inflateCount)

	if inflateBytes != "" && inflateCount != "" {
		count, countErr := strconv.Atoi(strings.TrimSpace(inflateCount))
		if countErr != nil || count <= 0 {
			// Invalid count, write default 1-byte padding
			if writeErr := os.WriteFile(paddingFile, []byte{0x00}, 0644); writeErr != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = fmt.Sprintf("Failed to write default padding file: %v", writeErr)
				return payloadBuildResponse
			}
		} else {
			// Parse hex bytes like "0x41,0x42" or "0x90"
			bytePattern, parseErr := parseInflateHexBytes(inflateBytes)
			if parseErr != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = fmt.Sprintf("Failed to parse inflate bytes: %v", parseErr)
				return payloadBuildResponse
			}
			// Build the full padding data by repeating the pattern count times
			paddingData := generatePaddingData(bytePattern, count)
			if writeErr := os.WriteFile(paddingFile, paddingData, 0644); writeErr != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = fmt.Sprintf("Failed to write padding file: %v", writeErr)
				return payloadBuildResponse
			}
			// Verify the file was written correctly
			if fi, statErr := os.Stat(paddingFile); statErr == nil {
				fmt.Printf("[builder] Generated padding.bin: %d bytes (%d repetitions of %d-byte pattern), file on disk: %d bytes\n", len(paddingData), count, len(bytePattern), fi.Size())
			} else {
				fmt.Printf("[builder] Generated padding.bin: %d bytes (%d repetitions of %d-byte pattern), stat error: %v\n", len(paddingData), count, len(bytePattern), statErr)
			}
		}
	} else {
		// No inflation requested, write minimal default
		fmt.Printf("[builder] No inflation requested, writing default 1-byte padding.bin\n")
		if writeErr := os.WriteFile(paddingFile, []byte{0x00}, 0644); writeErr != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildStdErr = fmt.Sprintf("Failed to write default padding file: %v", writeErr)
			return payloadBuildResponse
		}
	}
	// Defer cleanup: restore default padding.bin after build completes
	defer func() {
		if writeErr := os.WriteFile(paddingFile, []byte{0x00}, 0644); writeErr != nil {
			fmt.Printf("[builder] Warning: failed to restore default padding file: %v\n", writeErr)
		}
	}()

	// PE Resource Embedding (Windows only)
	agentCodeDir := "./fawkes/agent_code/"
	if targetOs == "windows" {
		peConfig, peErr := collectPEResourceConfig(payloadBuildMsg)
		if peErr != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildStdErr = fmt.Sprintf("PE resource config error: %v", peErr)
			return payloadBuildResponse
		}
		if peConfig.hasResources() {
			peReport, peErr := generatePEResources(agentCodeDir, architecture, peConfig)
			if peErr != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = fmt.Sprintf("PE resource generation failed: %v", peErr)
				mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
					PayloadUUID: payloadBuildMsg.PayloadUUID,
					StepName:    "PE Resources",
					StepSuccess: false,
					StepStdout:  fmt.Sprintf("Failed: %v", peErr),
				})
				return payloadBuildResponse
			}
			// Defer cleanup of .syso file
			sysoFile := filepath.Join(agentCodeDir, fmt.Sprintf("rsrc_windows_%s.syso", architecture))
			defer os.Remove(sysoFile)
			mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
				PayloadUUID: payloadBuildMsg.PayloadUUID,
				StepName:    "PE Resources",
				StepSuccess: true,
				StepStdout:  peReport,
			})
		} else {
			mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
				PayloadUUID: payloadBuildMsg.PayloadUUID,
				StepName:    "PE Resources",
				StepSuccess: true,
				StepStdout:  "No PE resources requested — skipping (default Go binary metadata)",
			})
		}
	} else {
		mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
			PayloadUUID: payloadBuildMsg.PayloadUUID,
			StepName:    "PE Resources",
			StepSuccess: true,
			StepStdout:  fmt.Sprintf("Skipped — PE resources only apply to Windows (target: %s)", targetOs),
		})
	}

	// Construct the build command and output filename
	cmdResult := constructBuildCommand(buildCommandConfig{
		targetOs:      targetOs,
		goarch:        architecture,
		mode:          mode,
		garble:        garble,
		c2ProfileName: payloadBuildMsg.C2Profiles[0].Name,
		payloadUUID:   payloadBuildMsg.PayloadUUID,
		macOSVersion:  macOSVersion,
		ldflags:       ldflags,
		buildParams:   payloadBuildMsg.BuildParameters,
	})
	command := cmdResult.command
	payloadName := cmdResult.payloadName

	// Report configuring step with padding info
	configuringOutput := fmt.Sprintf("Successfully configured\n%s", command)
	if inflateBytes != "" && inflateCount != "" {
		configuringOutput += fmt.Sprintf("\nBinary inflation: bytes=%s count=%s", inflateBytes, inflateCount)
	}
	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
		PayloadUUID: payloadBuildMsg.PayloadUUID,
		StepName:    "Configuring",
		StepSuccess: true,
		StepStdout:  configuringOutput,
	})

	// Compile the agent
	result, compileErr := executeCompilation(command, payloadBuildMsg.PayloadUUID, garble)
	if compileErr != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildMessage = "Compilation failed with errors"
		payloadBuildResponse.BuildStdErr = result.stderr
		payloadBuildResponse.BuildStdOut = result.stdout
		return payloadBuildResponse
	}
	if !garble {
		payloadBuildResponse.BuildStdErr = result.stderr
	}
	payloadBuildResponse.BuildStdOut = result.stdout

	// Post-build analysis: YARA scan and entropy analysis (informational only)
	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
		PayloadUUID: payloadBuildMsg.PayloadUUID,
		StepName:    "YARA Scan",
		StepSuccess: true,
		StepStdout:  runYARAScan(fmt.Sprintf("/build/%s", payloadName)),
	})
	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
		PayloadUUID: payloadBuildMsg.PayloadUUID,
		StepName:    "Entropy Analysis",
		StepSuccess: true,
		StepStdout:  runEntropyScan(fmt.Sprintf("/build/%s", payloadName)),
	})

	// Collect built payload (read binary, convert shellcode if needed, set filename)
	collectPayloadOutput(&payloadBuildResponse, payloadName, mode, targetOs)

	return payloadBuildResponse
}

// parseInflateHexBytes parses a comma-separated hex byte string like "0x41,0x42" or "0x90"
// into a byte slice. Returns an error if any part is not a valid hex byte.
func parseInflateHexBytes(hexStr string) ([]byte, error) {
	hexParts := strings.Split(hexStr, ",")
	var pattern []byte
	for _, part := range hexParts {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "0x")
		part = strings.TrimPrefix(part, "0X")
		val, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex byte '%s': %v", part, err)
		}
		pattern = append(pattern, byte(val))
	}
	return pattern, nil
}

// generatePaddingData repeats a byte pattern count times to create padding data.
func generatePaddingData(pattern []byte, count int) []byte {
	data := make([]byte, 0, len(pattern)*count)
	for i := 0; i < count; i++ {
		data = append(data, pattern...)
	}
	return data
}

func Initialize() {
	agentstructs.AllPayloadData.Get("fawkes").AddPayloadDefinition(payloadDefinition)
	agentstructs.AllPayloadData.Get("fawkes").AddBuildFunction(build)
	agentstructs.AllPayloadData.Get("fawkes").AddIcon(filepath.Join(".", "fawkes", "agentfunctions", "fawkes.svg"))
}

