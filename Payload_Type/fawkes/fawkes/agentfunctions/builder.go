package agentfunctions

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

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
		} else if key == "get_uri" || key == "post_uri" {
			val, err := payloadBuildMsg.C2Profiles[0].GetStringArg(key)
			if err != nil {
				payloadBuildResponse.Success = false
				payloadBuildResponse.BuildStdErr = err.Error()
				return payloadBuildResponse
			}
			// Use the first URI we encounter (get_uri or post_uri)
			ldflags += fmt.Sprintf(" -X '%s.endpointURI=%s'", fawkes_main_package, val)
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
	
	goarch := architecture
	tags := payloadBuildMsg.C2Profiles[0].Name
	command := fmt.Sprintf("rm -rf /deps; CGO_ENABLED=0 GOOS=%s GOARCH=%s ", targetOs, goarch)
	buildmodeflag := "default"
	if mode == "shared" {
		buildmodeflag = "c-shared"
		command = strings.Replace(command, "CGO_ENABLED=0", "CGO_ENABLED=1", 1)
	}
	goCmd := fmt.Sprintf("-tags %s -buildmode %s -ldflags \"%s\"", tags, buildmodeflag, ldflags)
	if mode == "shared" {
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
	command += fmt.Sprintf("%s -o /build/%s .", goCmd, payloadName)
	//"default-executable", "shared", "windows-shellcode"
	if mode == "shared" {
		if targetOs == "windows" {
			command += ".dll"
			payloadName += ".dll"
		} else if targetOs == "darwin" {
			command += ".dylib"
			payloadName += ".dylib"
		} else {
			command += ".so"
			payloadName += ".so"
		}
	} else if mode == "windows-shellcode" {
		command += ".dll"
		payloadName += ".dll"
		// need a DLL for the dll to shellcode conversion later
		// TODO - merlin sRDI for dll to shellcode option
	}

	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
		PayloadUUID: payloadBuildMsg.PayloadUUID,
		StepName:    "Configuring",
		StepSuccess: true,
		StepStdout:  fmt.Sprintf("Successfully configured\n%s", command),
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
		// TODO: Implement sRDI shellcode conversion
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildMessage = "Windows shellcode mode not implemented yet"
	} else {
		payloadBuildResponse.Payload = &payloadBytes
		payloadBuildResponse.Success = true
		payloadBuildResponse.BuildMessage = "Successfully built payload!"
	}

	//payloadBuildResponse.Status = agentstructs.PAYLOAD_BUILD_STATUS_ERROR
	return payloadBuildResponse
}

func Initialize() {
	agentstructs.AllPayloadData.Get("fawkes").AddPayloadDefinition(payloadDefinition)
	agentstructs.AllPayloadData.Get("fawkes").AddBuildFunction(build)
	agentstructs.AllPayloadData.Get("fawkes").AddIcon(filepath.Join(".", "fawkes", "agentfunctions", "fawkes.svg"))
}
