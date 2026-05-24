package agentfunctions

import (
	"strings"
	"testing"
)

// --- normalizeVersionString Tests ---

func TestNormalizeVersionString_ThreeComponents(t *testing.T) {
	got := normalizeVersionString("10.0.19041")
	if got != "10.0.19041.0" {
		t.Errorf("normalizeVersionString = %q, want %q", got, "10.0.19041.0")
	}
}

func TestNormalizeVersionString_TwoComponents(t *testing.T) {
	got := normalizeVersionString("1.0")
	if got != "1.0.0.0" {
		t.Errorf("normalizeVersionString = %q, want %q", got, "1.0.0.0")
	}
}

func TestNormalizeVersionString_FourComponents(t *testing.T) {
	got := normalizeVersionString("10.0.19041.3636")
	if got != "10.0.19041.3636" {
		t.Errorf("normalizeVersionString = %q, want %q", got, "10.0.19041.3636")
	}
}

func TestNormalizeVersionString_FiveComponents(t *testing.T) {
	// Should truncate to 4
	got := normalizeVersionString("1.2.3.4.5")
	if got != "1.2.3.4" {
		t.Errorf("normalizeVersionString = %q, want %q", got, "1.2.3.4")
	}
}

func TestNormalizeVersionString_SingleComponent(t *testing.T) {
	got := normalizeVersionString("5")
	if got != "5.0.0.0" {
		t.Errorf("normalizeVersionString = %q, want %q", got, "5.0.0.0")
	}
}

func TestNormalizeVersionString_Empty(t *testing.T) {
	got := normalizeVersionString("")
	if got != ".0.0.0" {
		// Empty splits to [""], pad to 4 = ["", "0", "0", "0"]
		t.Errorf("normalizeVersionString(\"\") = %q", got)
	}
}

// --- detectIconFormat Tests ---

func TestDetectIconFormat_ICO(t *testing.T) {
	data := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00}
	got := detectIconFormat(data)
	if got != "icon.ico" {
		t.Errorf("detectIconFormat(ICO) = %q, want %q", got, "icon.ico")
	}
}

func TestDetectIconFormat_PNG(t *testing.T) {
	data := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A}
	got := detectIconFormat(data)
	if got != "icon.png" {
		t.Errorf("detectIconFormat(PNG) = %q, want %q", got, "icon.png")
	}
}

func TestDetectIconFormat_Unknown(t *testing.T) {
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0} // JPEG magic
	got := detectIconFormat(data)
	if got != "icon.ico" {
		t.Errorf("detectIconFormat(JPEG) = %q, want %q (default)", got, "icon.ico")
	}
}

func TestDetectIconFormat_TooShort(t *testing.T) {
	data := []byte{0x00, 0x00}
	got := detectIconFormat(data)
	if got != "icon.ico" {
		t.Errorf("detectIconFormat(short) = %q, want %q (default)", got, "icon.ico")
	}
}

func TestDetectIconFormat_Empty(t *testing.T) {
	got := detectIconFormat(nil)
	if got != "icon.ico" {
		t.Errorf("detectIconFormat(nil) = %q, want %q (default)", got, "icon.ico")
	}
}

// --- hasResources Tests ---

func TestHasResources_Empty(t *testing.T) {
	cfg := &peResourceConfig{}
	if cfg.hasResources() {
		t.Error("empty config should not have resources")
	}
}

func TestHasResources_CompanyOnly(t *testing.T) {
	cfg := &peResourceConfig{Company: "Microsoft Corporation"}
	if !cfg.hasResources() {
		t.Error("config with Company should have resources")
	}
}

func TestHasResources_IconOnly(t *testing.T) {
	cfg := &peResourceConfig{IconData: []byte{0x00, 0x00, 0x01, 0x00}}
	if !cfg.hasResources() {
		t.Error("config with IconData should have resources")
	}
}

func TestHasResources_ManifestOnly(t *testing.T) {
	cfg := &peResourceConfig{ManifestLevel: "as invoker"}
	if !cfg.hasResources() {
		t.Error("config with ManifestLevel should have resources")
	}
}

func TestHasResources_AllFields(t *testing.T) {
	cfg := &peResourceConfig{
		Company:       "Test Corp",
		Description:   "Test App",
		Product:       "Test Product",
		Version:       "1.0.0.0",
		Copyright:     "(c) Test",
		OriginalFile:  "test.exe",
		IconData:      []byte{0x00},
		ManifestLevel: "highest available",
	}
	if !cfg.hasResources() {
		t.Error("fully populated config should have resources")
	}
}

// --- buildWinresConfig Tests ---

func TestBuildWinresConfig_VersionInfo(t *testing.T) {
	cfg := &peResourceConfig{
		Company:      "Microsoft Corporation",
		Description:  "Test Description",
		Product:      "Windows Test",
		Version:      "10.0.19041",
		Copyright:    "(c) Microsoft",
		OriginalFile: "test.exe",
	}

	config := buildWinresConfig(cfg, "")
	rtVersion, ok := config["RT_VERSION"]
	if !ok {
		t.Fatal("RT_VERSION should be present")
	}

	// Navigate the nested structure
	v1 := rtVersion.(map[string]interface{})["#1"]
	if v1 == nil {
		t.Fatal("RT_VERSION[#1] should be present")
	}
	v0000 := v1.(map[string]interface{})["0000"]
	if v0000 == nil {
		t.Fatal("RT_VERSION[#1][0000] should be present")
	}

	fixed := v0000.(map[string]interface{})["fixed"].(map[string]string)
	if fixed["file_version"] != "10.0.19041.0" {
		t.Errorf("file_version = %q, want 10.0.19041.0", fixed["file_version"])
	}

	info := v0000.(map[string]interface{})["info"].(map[string]interface{})["0409"].(map[string]string)
	if info["CompanyName"] != "Microsoft Corporation" {
		t.Errorf("CompanyName = %q", info["CompanyName"])
	}
}

func TestBuildWinresConfig_Icon(t *testing.T) {
	cfg := &peResourceConfig{}
	config := buildWinresConfig(cfg, "icon.ico")

	rtIcon, ok := config["RT_GROUP_ICON"]
	if !ok {
		t.Fatal("RT_GROUP_ICON should be present")
	}
	app := rtIcon.(map[string]interface{})["APP"]
	filename := app.(map[string]interface{})["0000"]
	if filename != "icon.ico" {
		t.Errorf("icon filename = %v, want icon.ico", filename)
	}
}

func TestBuildWinresConfig_Manifest(t *testing.T) {
	cfg := &peResourceConfig{ManifestLevel: "require administrator"}
	config := buildWinresConfig(cfg, "")

	rtManifest, ok := config["RT_MANIFEST"]
	if !ok {
		t.Fatal("RT_MANIFEST should be present")
	}
	m1 := rtManifest.(map[string]interface{})["#1"]
	m0409 := m1.(map[string]interface{})["0409"].(map[string]interface{})
	if m0409["execution-level"] != "require administrator" {
		t.Errorf("execution-level = %v", m0409["execution-level"])
	}
}

func TestBuildWinresConfig_Empty(t *testing.T) {
	cfg := &peResourceConfig{}
	config := buildWinresConfig(cfg, "")

	if len(config) != 0 {
		t.Errorf("empty config should produce empty winres config, got %d keys", len(config))
	}
}

// --- buildPEResourceReport Tests ---

func TestBuildPEResourceReport_Full(t *testing.T) {
	cfg := &peResourceConfig{
		Company:       "Microsoft Corporation",
		Description:   "Windows Notepad",
		Product:       "Microsoft Windows",
		Version:       "10.0.19041.3636",
		Copyright:     "(c) Microsoft",
		OriginalFile:  "notepad.exe",
		InternalName:  "Notepad",
		IconData:      []byte{0x00, 0x00, 0x01, 0x00, 0x01},
		ManifestLevel: "as invoker",
		PresetName:    "notepad",
	}

	report := buildPEResourceReport(cfg, 4096)

	if !strings.Contains(report, "PE Resource Embedding") {
		t.Error("report should contain header")
	}
	if !strings.Contains(report, "Preset: notepad") {
		t.Error("report should contain preset name")
	}
	if !strings.Contains(report, "4096 bytes") {
		t.Error("report should contain syso size")
	}
	if !strings.Contains(report, "Microsoft Corporation") {
		t.Error("report should contain company")
	}
	if !strings.Contains(report, "10.0.19041.3636") {
		t.Error("report should contain version")
	}
	if !strings.Contains(report, "icon.ico") {
		t.Error("report should contain icon format")
	}
	if !strings.Contains(report, "as invoker") {
		t.Error("report should contain manifest level")
	}
}

func TestBuildPEResourceReport_MinimalConfig(t *testing.T) {
	cfg := &peResourceConfig{
		Company: "Test",
		Version: "1.0",
	}

	report := buildPEResourceReport(cfg, 1024)

	if !strings.Contains(report, "CompanyName") {
		t.Error("report should contain CompanyName")
	}
	if !strings.Contains(report, "FileVersion") {
		t.Error("report should contain FileVersion")
	}
	// Should NOT contain icon or manifest sections
	if strings.Contains(report, "Icon:") {
		t.Error("report should not contain Icon section")
	}
	if strings.Contains(report, "Manifest:") {
		t.Error("report should not contain Manifest section")
	}
}

func TestBuildPEResourceReport_NoPreset(t *testing.T) {
	cfg := &peResourceConfig{
		Company: "Custom Corp",
	}

	report := buildPEResourceReport(cfg, 512)

	if strings.Contains(report, "Preset:") {
		t.Error("report should not contain Preset line when PresetName is empty")
	}
}

// --- pePresets Tests ---

func TestPEPresets_NotepadExists(t *testing.T) {
	p, ok := pePresets["notepad"]
	if !ok {
		t.Fatal("notepad preset should exist")
	}
	if p.Company != "Microsoft Corporation" {
		t.Errorf("notepad company = %q", p.Company)
	}
	if p.OriginalFile != "NOTEPAD.EXE" {
		t.Errorf("notepad original file = %q", p.OriginalFile)
	}
}

func TestPEPresets_SvchostExists(t *testing.T) {
	p, ok := pePresets["svchost"]
	if !ok {
		t.Fatal("svchost preset should exist")
	}
	if p.Description != "Host Process for Windows Services" {
		t.Errorf("svchost description = %q", p.Description)
	}
}

func TestPEPresets_AllHaveRequiredFields(t *testing.T) {
	for name, p := range pePresets {
		if p.Company == "" {
			t.Errorf("preset %q missing Company", name)
		}
		if p.Description == "" {
			t.Errorf("preset %q missing Description", name)
		}
		if p.Version == "" {
			t.Errorf("preset %q missing Version", name)
		}
	}
}
