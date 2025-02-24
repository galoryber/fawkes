package fawkesbuild

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/google/uuid"
	"github.com/pelletier/go-toml"
	"golang.org/x/exp/slices"
)

var payloadDefinition = agentstructs.PayloadType{
	Name:                                   "fawkes",
	FileExtension:                          "bin",
	Author:                                 "@galoryber",
	SupportedOS:                            []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
	Wrapper:                                false,
	CanBeWrappedByTheFollowingPayloadTypes: []string{},
	SupportsDynamicLoading:                 false,
	Description:                            "A Golang agent",
	SupportedC2Profiles:                    []string{"http"},
	MythicEncryptsData:                     true,
	BuildParameters: []agentstructs.BuildParameter{
		{
			Name:          "mode",
			Description:   "Choose the build mode option. Select default for executables, c-shared for a .dylib or .so file, or c-archive for a .Zip containing C source code with an archive and header file",
			Required:      false,
			DefaultValue:  "default",
			Choices:       []string{"default", "c-archive", "c-shared"},
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_CHOOSE_ONE,
		},
		{
			Name:          "architecture",
			Description:   "Choose the agent's architecture",
			Required:      false,
			DefaultValue:  "AMD_x64",
			Choices:       []string{"AMD_x64", "ARM_x64"},
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_CHOOSE_ONE,
		},
		{
			Name:          "proxy_bypass",
			Description:   "Ignore HTTP proxy environment settings configured on the target host?",
			Required:      false,
			DefaultValue:  false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
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
	},
}

func build(payloadBuildMsg agentstructs.PayloadBuildMessage) agentstructs.PayloadBuildResponse {
	payloadBuildResponse := agentstructs.PayloadBuildResponse{
		PayloadUUID:        payloadBuildMsg.PayloadUUID,
		Success:            true,
		UpdatedCommandList: &payloadBuildMsg.CommandList,
	}
	// adding my own payload build response outputs to see if we actually see these in Mythic
	if true == true {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildMessage = "Gary Test at beginning of build.go"
		return payloadBuildResponse
	}

	if len(payloadBuildMsg.C2Profiles) == 0 {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = "Failed to build - must select at least one C2 Profile"
		return payloadBuildResponse
	}
	macOSVersion := "10.12"
	targetOs := "linux"
	if payloadBuildMsg.SelectedOS == "macOS" {
		targetOs = "darwin"
	} else if payloadBuildMsg.SelectedOS == "Windows" {
		targetOs = "windows"
	}
	egress_order, err := payloadBuildMsg.BuildParameters.GetArrayArg("egress_order")
	if err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = err.Error()
		return payloadBuildResponse
	}
	egress_failover, err := payloadBuildMsg.BuildParameters.GetChooseOneArg("egress_failover")
	if err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = err.Error()
		return payloadBuildResponse
	}
	debug, err := payloadBuildMsg.BuildParameters.GetBooleanArg("debug")
	if err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = err.Error()
		return payloadBuildResponse
	}
	static, err := payloadBuildMsg.BuildParameters.GetBooleanArg("static")
	if err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = err.Error()
		return payloadBuildResponse
	}
	if static && targetOs == "darwin" {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = "Cannot currently build fully static library for macOS"
		return payloadBuildResponse
	}
	failedConnectionCountThresholdString, err := payloadBuildMsg.BuildParameters.GetNumberArg("failover_threshold")
	if err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = err.Error()
		return payloadBuildResponse
	}
	// This package path is used with Go's "-X" link flag to set the value string variables in code at compile
	// time. This is how each profile's configurable options are passed in.
	freyja_repo_profile := "github.com/MythicAgents/freyja/Payload_Type/freyja/agent_code/pkg/profiles"
	freyja_repo_utils := "github.com/MythicAgents/freyja/Payload_Type/freyja/agent_code/pkg/utils"

	// Build Go link flags that are passed in at compile time through the "-ldflags=" argument
	// https://golang.org/cmd/link/
	ldflags := ""
	if static {
		ldflags += fmt.Sprintf("-extldflags=-static -s -w -X '%s.UUID=%s'", freyja_repo_profile, payloadBuildMsg.PayloadUUID)
	} else {
		ldflags += fmt.Sprintf("-s -w -X '%s.UUID=%s'", freyja_repo_profile, payloadBuildMsg.PayloadUUID)
	}
	ldflags += fmt.Sprintf(" -X '%s.debugString=%v'", freyja_repo_utils, debug)
	ldflags += fmt.Sprintf(" -X '%s.egress_failover=%s'", freyja_repo_profile, egress_failover)
	ldflags += fmt.Sprintf(" -X '%s.failedConnectionCountThresholdString=%v'", freyja_repo_profile, failedConnectionCountThresholdString)
	if egressBytes, err := json.Marshal(egress_order); err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = err.Error()
		return payloadBuildResponse
	} else {
		stringBytes := base64.StdEncoding.EncodeToString(egressBytes)
		//stringBytes = strings.ReplaceAll(stringBytes, "\"", "\\\"")
		ldflags += fmt.Sprintf(" -X '%s.egress_order=%s'", freyja_repo_profile, stringBytes)
	}
	// Iterate over the C2 profile parameters and associated variable through Go's "-X" link flag
	for index, _ := range payloadBuildMsg.C2Profiles {
		initialConfig := make(map[string]interface{})
		for _, key := range payloadBuildMsg.C2Profiles[index].GetArgNames() {
			if key == "AESPSK" {
				//cryptoVal := val.(map[string]interface{})
				cryptoVal, err := payloadBuildMsg.C2Profiles[index].GetCryptoArg(key)
				if err != nil {
					payloadBuildResponse.Success = false
					payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
					return payloadBuildResponse
				}
				initialConfig[key] = cryptoVal.EncKey
				//ldflags += fmt.Sprintf(" -X '%s.%s_%s=%s'", freyja_repo_profile, payloadBuildMsg.C2Profiles[index].Name, key, cryptoVal.EncKey)
			} else if key == "headers" {
				headers, err := payloadBuildMsg.C2Profiles[index].GetDictionaryArg(key)
				if err != nil {
					payloadBuildResponse.Success = false
					payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
					return payloadBuildResponse
				}
				initialConfig[key] = headers
				/*
					if jsonBytes, err := json.Marshal(headers); err != nil {
						payloadBuildResponse.Success = false
						payloadBuildResponse.BuildStdErr = err.Error()
						return payloadBuildResponse
					} else {
						stringBytes := string(jsonBytes)
						stringBytes = strings.ReplaceAll(stringBytes, "\"", "\\\"")
						ldflags += fmt.Sprintf(" -X '%s.%s_%s=%s'", freyja_repo_profile, payloadBuildMsg.C2Profiles[index].Name, key, stringBytes)
					}

				*/
			} else if key == "raw_c2_config" {
				agentConfigString, err := payloadBuildMsg.C2Profiles[index].GetStringArg(key)
				if err != nil {
					payloadBuildResponse.Success = false
					payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
					return payloadBuildResponse
				}
				configData, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
					AgentFileID: agentConfigString,
				})
				if err != nil {
					payloadBuildResponse.Success = false
					payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
					return payloadBuildResponse
				}
				if !configData.Success {
					payloadBuildResponse.Success = false
					payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + configData.Error
					return payloadBuildResponse
				}
				tomlConfig := make(map[string]interface{})
				err = json.Unmarshal(configData.Content, &tomlConfig)
				if err != nil {
					err = toml.Unmarshal(configData.Content, &tomlConfig)
					if err != nil {
						payloadBuildResponse.Success = false
						payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
						return payloadBuildResponse
					}
				}
				initialConfig[key] = tomlConfig
				/*
				   agentConfigString = strings.ReplaceAll(string(configData.Content), "\\", "\\\\")
				   agentConfigString = strings.ReplaceAll(agentConfigString, "\"", "\\\"")
				   agentConfigString = strings.ReplaceAll(agentConfigString, "\n", "")
				   ldflags += fmt.Sprintf(" -X '%s.%s_%s=%s'", freyja_repo_profile, payloadBuildMsg.C2Profiles[index].Name, key, agentConfigString)
				*/
			} else if slices.Contains([]string{"callback_jitter", "callback_interval", "callback_port", "port", "callback_port", "failover_threshold"}, key) {

				val, err := payloadBuildMsg.C2Profiles[index].GetNumberArg(key)
				if err != nil {
					stringVal, err := payloadBuildMsg.C2Profiles[index].GetStringArg(key)
					if err != nil {
						payloadBuildResponse.Success = false
						payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
						return payloadBuildResponse
					}
					realVal, err := strconv.Atoi(stringVal)
					if err != nil {
						payloadBuildResponse.Success = false
						payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
						return payloadBuildResponse
					}
					initialConfig[key] = realVal
				} else {
					initialConfig[key] = int(val)
				}

				//ldflags += fmt.Sprintf(" -X '%s.%s_%s=%v'", poseidon_repo_profile, payloadBuildMsg.C2Profiles[index].Name, key, val)
			} else if slices.Contains([]string{"encrypted_exchange_check"}, key) {
				val, err := payloadBuildMsg.C2Profiles[index].GetBooleanArg(key)
				if err != nil {
					stringVal, err := payloadBuildMsg.C2Profiles[index].GetStringArg(key)
					if err != nil {
						payloadBuildResponse.Success = false
						payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
						return payloadBuildResponse
					}
					initialConfig[key] = stringVal == "T"
				} else {
					initialConfig[key] = val
				}
			} else if slices.Contains([]string{"callback_domains"}, key) {
				val, err := payloadBuildMsg.C2Profiles[index].GetArrayArg(key)
				if err != nil {
					payloadBuildResponse.Success = false
					payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
					return payloadBuildResponse
				}
				initialConfig[key] = val
			} else {
				val, err := payloadBuildMsg.C2Profiles[index].GetStringArg(key)
				if err != nil {
					payloadBuildResponse.Success = false
					payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
					return payloadBuildResponse
				}
				if key == "proxy_port" {
					if val == "" {
						initialConfig[key] = 0
					} else {
						intval, err := strconv.Atoi(val)
						if err != nil {
							payloadBuildResponse.Success = false
							payloadBuildResponse.BuildStdErr = "Key error: " + key + "\n" + err.Error()
							return payloadBuildResponse
						}
						initialConfig[key] = intval
					}
				} else {
					initialConfig[key] = val
				}

			}
		}
		initialConfigBytes, err := json.Marshal(initialConfig)
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildStdErr = err.Error()
			return payloadBuildResponse
		}
		initialConfigBase64 := base64.StdEncoding.EncodeToString(initialConfigBytes)
		payloadBuildResponse.BuildStdOut += fmt.Sprintf("%s's config: \n%v\n", payloadBuildMsg.C2Profiles[index].Name, string(initialConfigBytes))
		ldflags += fmt.Sprintf(" -X '%s.%s_%s=%v'", freyja_repo_profile, payloadBuildMsg.C2Profiles[index].Name, "initial_config", initialConfigBase64)
	}

	proxyBypass, err := payloadBuildMsg.BuildParameters.GetBooleanArg("proxy_bypass")
	if err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildStdErr = err.Error()
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
	ldflags += fmt.Sprintf(" -X '%s.proxy_bypass=%v'", freyja_repo_profile, proxyBypass)
	ldflags += " -buildid="
	goarch := "amd64"
	if architecture == "ARM_x64" {
		goarch = "arm64"
	}
	tags := []string{}
	if static {
		tags = []string{"osusergo", "netgo"}
	}
	for index, _ := range payloadBuildMsg.C2Profiles {
		tags = append(tags, payloadBuildMsg.C2Profiles[index].Name)
	}
	if mode == "c-shared" {
		tags = append(tags, "shared")
	}
	command := fmt.Sprintf("CGO_ENABLED=1 GOOS=%s GOARCH=%s ", targetOs, goarch)
	goCmd := fmt.Sprintf("-tags %s -buildmode %s -ldflags \"%s\"", strings.Join(tags, ","), mode, ldflags)
	if targetOs == "darwin" {
		command += "CC=o64-clang CXX=o64-clang++ "
	} else if targetOs == "windows" {
		command += "CC=x86_64-w64-mingw32-gcc "
	} else {
		if goarch == "arm64" {
			command += "CC=aarch64-linux-gnu-gcc "
		} else {
			command += "CC=x86_64-linux-gnu-gcc "
		}
	}
	command += "GOGARBLE=* "
	if garble {
		command += "/go/bin/garble -tiny -literals -debug -seed random build "
	} else {
		command += "go build "
	}
	payloadName := fmt.Sprintf("%s-%s", payloadBuildMsg.PayloadUUID, targetOs)
	command += fmt.Sprintf("%s -o /build/%s", goCmd, payloadName)
	if targetOs == "darwin" {
		command += fmt.Sprintf("-%s", macOSVersion)
		payloadName += fmt.Sprintf("-%s", macOSVersion)
	}
	command += fmt.Sprintf("-%s", goarch)
	payloadName += fmt.Sprintf("-%s", goarch)
	if mode == "c-shared" {
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
	} else if mode == "c-archive" {
		command += ".a"
		payloadName += ".a"
	}

	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
		PayloadUUID: payloadBuildMsg.PayloadUUID,
		StepName:    "Configuring",
		StepSuccess: true,
		StepStdout:  fmt.Sprintf("Successfully configured\n%s", command),
	})
	if garble {
		mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
			PayloadUUID: payloadBuildMsg.PayloadUUID,
			StepName:    "Garble",
			StepSuccess: true,
			StepStdout:  fmt.Sprintf("Successfully added in garble\n"),
		})
	} else {
		mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
			PayloadUUID: payloadBuildMsg.PayloadUUID,
			StepName:    "Garble",
			StepSkip:    true,
			StepStdout:  fmt.Sprintf("Skipped Garble\n"),
		})
	}
	cmd := exec.Command("/bin/bash")
	cmd.Stdin = strings.NewReader(command)
	cmd.Dir = "./freyja/agent_code/"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildMessage = "Compilation failed with errors"
		payloadBuildResponse.BuildStdErr += stderr.String() + "\n" + err.Error()
		payloadBuildResponse.BuildStdOut += stdout.String()
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
	payloadBuildResponse.BuildStdOut += stdout.String()

	if payloadBytes, err := os.ReadFile(fmt.Sprintf("/build/%s", payloadName)); err != nil {
		payloadBuildResponse.Success = false
		payloadBuildResponse.BuildMessage = "Failed to find final payload"
	} else if mode == "c-archive" && targetOs == "darwin" {
		zipUUID := uuid.New().String()
		archive, err := os.Create(fmt.Sprintf("/build/%s", zipUUID))
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = "Failed to make temp archive on disk"
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\n%v\n", err)
			return payloadBuildResponse
		}
		zipWriter := zip.NewWriter(archive)
		fileWriter, err := zipWriter.Create("freyja-darwin-10.12-amd64.a")
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = "Failed to save payload to zip"
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\n%v\n", err)
			archive.Close()
			return payloadBuildResponse
		}
		_, err = io.Copy(fileWriter, bytes.NewReader(payloadBytes))
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = "Failed to write payload to zip"
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\n%v\n", err)
			archive.Close()
			return payloadBuildResponse
		}
		headerName := fmt.Sprintf("%s.h", payloadName[:len(payloadName)-2])
		headerWriter, err := zipWriter.Create("freyja-darwin-10.12-amd64.h")
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = "Failed to save header to zip"
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\n%v\n", err)
			archive.Close()
			return payloadBuildResponse
		}
		headerFile, err := os.Open(fmt.Sprintf("/build/%s", headerName))
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = "Failed to open header to zip"
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\n%v\n", err)
			archive.Close()
			return payloadBuildResponse
		}
		_, err = io.Copy(headerWriter, headerFile)
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = "Failed to write header to zip"
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\n%v\n", err)
			archive.Close()
			return payloadBuildResponse
		}
		sharedWriter, err := zipWriter.Create("sharedlib-darwin-linux.c")
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = "Failed to save payload to zip"
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\n%v\n", err)
			archive.Close()
			return payloadBuildResponse
		}
		sharedLib, err := os.Open("./freyja/agent_code/sharedlib/sharedlib-darwin-linux.c")
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = "Failed to save sharedlib to zip"
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\n%v\n", err)
			archive.Close()
			return payloadBuildResponse
		}
		_, err = io.Copy(sharedWriter, sharedLib)
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = "Failed to write sharedlib to zip"
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\n%v\n", err)
			archive.Close()
			return payloadBuildResponse
		}
		zipWriter.Close()
		archive.Close()
		archiveBytes, err := os.ReadFile(fmt.Sprintf("/build/%s", zipUUID))
		if err != nil {
			payloadBuildResponse.Success = false
			payloadBuildResponse.BuildMessage = "Failed to read final zip"
			payloadBuildResponse.BuildStdErr += fmt.Sprintf("\n%v\n", err)
			return payloadBuildResponse
		}
		payloadBuildResponse.Payload = &archiveBytes
		payloadBuildResponse.Success = true
		payloadBuildResponse.BuildMessage = "Successfully built payload!"
		if !strings.HasSuffix(payloadBuildMsg.Filename, ".zip") {
			updatedFilename := fmt.Sprintf("%s.zip", payloadBuildMsg.Filename)
			payloadBuildResponse.UpdatedFilename = &updatedFilename
		}
	} else {
		payloadBuildResponse.Payload = &payloadBytes
		payloadBuildResponse.Success = true
		payloadBuildResponse.BuildMessage = "Successfully built payload!"
	}

	//payloadBuildResponse.Status = agentstructs.PAYLOAD_BUILD_STATUS_ERROR
	return payloadBuildResponse
}

func Initialize() {
	agentstructs.AllPayloadData.Get("fawkesAgent").AddPayloadDefinition(payloadDefinition)
	agentstructs.AllPayloadData.Get("fawkesAgent").AddBuildFunction(build)
	//agentstructs.AllPayloadData.Get("freyja").AddOnNewCallbackFunction(onNewCallback)
	agentstructs.AllPayloadData.Get("fawkesAgent").AddIcon(filepath.Join(".", "basic_agent", "agentfunctions", "fawkes.svg"))
}
