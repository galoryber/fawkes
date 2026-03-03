package commands

import (
	"testing"
)

// --- parseIoregSerial tests ---

func TestParseIoregSerial_Standard(t *testing.T) {
	output := `+-o Root  <class IORegistryEntry, id 0x100000100, retain 21>
    {
      "IOPlatformSerialNumber" = "C02FN1ABCD12"
      "IOPlatformUUID" = "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
      "model" = <"Mac14,2">
    }`
	serial := parseIoregSerial(output)
	if serial != "C02FN1ABCD12" {
		t.Errorf("expected 'C02FN1ABCD12', got %q", serial)
	}
}

func TestParseIoregSerial_M1MacMini(t *testing.T) {
	output := `+-o Root  <class IORegistryEntry>
    {
      "manufacturer" = <"Apple Inc.">
      "IOPlatformSerialNumber" = "FVFDX1234567"
      "target-type" = "J274"
    }`
	serial := parseIoregSerial(output)
	if serial != "FVFDX1234567" {
		t.Errorf("expected 'FVFDX1234567', got %q", serial)
	}
}

func TestParseIoregSerial_NoSerial(t *testing.T) {
	output := `+-o Root  <class IORegistryEntry>
    {
      "IOPlatformUUID" = "A1B2C3D4"
    }`
	serial := parseIoregSerial(output)
	if serial != "" {
		t.Errorf("expected empty string, got %q", serial)
	}
}

func TestParseIoregSerial_EmptyOutput(t *testing.T) {
	serial := parseIoregSerial("")
	if serial != "" {
		t.Errorf("expected empty string, got %q", serial)
	}
}

func TestParseIoregSerial_ExtraWhitespace(t *testing.T) {
	output := `      "IOPlatformSerialNumber"   =   "ABC123DEF456"  `
	serial := parseIoregSerial(output)
	if serial != "ABC123DEF456" {
		t.Errorf("expected 'ABC123DEF456', got %q", serial)
	}
}

// --- parseSpctlStatus tests ---

func TestParseSpctlStatus_Enabled(t *testing.T) {
	result := parseSpctlStatus("assessments enabled\n")
	if result != "enabled" {
		t.Errorf("expected 'enabled', got %q", result)
	}
}

func TestParseSpctlStatus_Disabled(t *testing.T) {
	result := parseSpctlStatus("assessments disabled\n")
	if result != "disabled" {
		t.Errorf("expected 'disabled', got %q", result)
	}
}

func TestParseSpctlStatus_Empty(t *testing.T) {
	result := parseSpctlStatus("")
	if result != "unknown" {
		t.Errorf("expected 'unknown', got %q", result)
	}
}

func TestParseSpctlStatus_Whitespace(t *testing.T) {
	result := parseSpctlStatus("   assessments enabled   \n")
	if result != "enabled" {
		t.Errorf("expected 'enabled', got %q", result)
	}
}

func TestParseSpctlStatus_UnexpectedOutput(t *testing.T) {
	result := parseSpctlStatus("some unexpected output")
	if result != "some unexpected output" {
		t.Errorf("expected raw output, got %q", result)
	}
}

// --- parseFdesetupStatus tests ---

func TestParseFdesetupStatus_On(t *testing.T) {
	result := parseFdesetupStatus("FileVault is On.\n")
	if result != "on" {
		t.Errorf("expected 'on', got %q", result)
	}
}

func TestParseFdesetupStatus_Off(t *testing.T) {
	result := parseFdesetupStatus("FileVault is Off.\n")
	if result != "off" {
		t.Errorf("expected 'off', got %q", result)
	}
}

func TestParseFdesetupStatus_Encrypting(t *testing.T) {
	result := parseFdesetupStatus("Encryption in progress: Percent completed = 45\n")
	if result != "encrypting" {
		t.Errorf("expected 'encrypting', got %q", result)
	}
}

func TestParseFdesetupStatus_Decrypting(t *testing.T) {
	result := parseFdesetupStatus("Decryption in progress: Percent completed = 80\n")
	if result != "decrypting" {
		t.Errorf("expected 'decrypting', got %q", result)
	}
}

func TestParseFdesetupStatus_Empty(t *testing.T) {
	result := parseFdesetupStatus("")
	if result != "unknown" {
		t.Errorf("expected 'unknown', got %q", result)
	}
}

func TestParseFdesetupStatus_CaseInsensitive(t *testing.T) {
	result := parseFdesetupStatus("FILEVAULT IS ON.\n")
	if result != "on" {
		t.Errorf("expected 'on', got %q", result)
	}
}

func TestParseFdesetupStatus_Unknown(t *testing.T) {
	result := parseFdesetupStatus("Error: Command requires FileVault to be active")
	if result != "Error: Command requires FileVault to be active" {
		t.Errorf("expected raw output for unrecognized status, got %q", result)
	}
}

// --- parseMDMEnrollment tests ---

func TestParseMDMEnrollment_NotEnrolled(t *testing.T) {
	output := `Enrolled via DEP: No
MDM enrollment: No`
	info := parseMDMEnrollment(output)
	if info.Enrolled {
		t.Error("expected not enrolled")
	}
	if info.MDMEnrolled {
		t.Error("expected MDM not enrolled")
	}
	if info.DEPEnrolled {
		t.Error("expected DEP not enrolled")
	}
}

func TestParseMDMEnrollment_MDMOnly(t *testing.T) {
	output := `Enrolled via DEP: No
MDM enrollment: Yes`
	info := parseMDMEnrollment(output)
	if !info.Enrolled {
		t.Error("expected enrolled")
	}
	if !info.MDMEnrolled {
		t.Error("expected MDM enrolled")
	}
	if info.DEPEnrolled {
		t.Error("expected DEP not enrolled")
	}
}

func TestParseMDMEnrollment_DEPAndMDM(t *testing.T) {
	output := `Enrolled via DEP: Yes
MDM enrollment: Yes`
	info := parseMDMEnrollment(output)
	if !info.Enrolled {
		t.Error("expected enrolled")
	}
	if !info.MDMEnrolled {
		t.Error("expected MDM enrolled")
	}
	if !info.DEPEnrolled {
		t.Error("expected DEP enrolled")
	}
}

func TestParseMDMEnrollment_AlternateFormat(t *testing.T) {
	output := `DEP Enrollment: Yes
MDM Enrollment: Yes
Server URL: https://mdm.example.com`
	info := parseMDMEnrollment(output)
	if !info.Enrolled {
		t.Error("expected enrolled")
	}
	if !info.MDMEnrolled {
		t.Error("expected MDM enrolled")
	}
	if !info.DEPEnrolled {
		t.Error("expected DEP enrolled")
	}
}

func TestParseMDMEnrollment_Empty(t *testing.T) {
	info := parseMDMEnrollment("")
	if info.Enrolled {
		t.Error("expected not enrolled on empty input")
	}
}

func TestParseMDMEnrollment_PreservesRawOutput(t *testing.T) {
	output := "some raw output"
	info := parseMDMEnrollment(output)
	if info.RawOutput != "some raw output" {
		t.Errorf("expected raw output preserved, got %q", info.RawOutput)
	}
}

// --- parseRosettaStatus tests ---

func TestParseRosettaStatus_NativeAppleSilicon(t *testing.T) {
	isAppleSilicon, isRosetta := parseRosettaStatus("0\n", "Apple M2\n")
	if !isAppleSilicon {
		t.Error("expected Apple Silicon detected")
	}
	if isRosetta {
		t.Error("expected Rosetta not active")
	}
}

func TestParseRosettaStatus_RosettaTranslated(t *testing.T) {
	isAppleSilicon, isRosetta := parseRosettaStatus("1\n", "Apple M1 Pro\n")
	if !isAppleSilicon {
		t.Error("expected Apple Silicon detected")
	}
	if !isRosetta {
		t.Error("expected Rosetta active")
	}
}

func TestParseRosettaStatus_IntelMac(t *testing.T) {
	isAppleSilicon, isRosetta := parseRosettaStatus("0\n", "Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz\n")
	if isAppleSilicon {
		t.Error("expected Intel (not Apple Silicon)")
	}
	if isRosetta {
		t.Error("expected Rosetta not active on Intel")
	}
}

func TestParseRosettaStatus_EmptyBrand(t *testing.T) {
	isAppleSilicon, isRosetta := parseRosettaStatus("", "")
	if isAppleSilicon {
		t.Error("expected no detection on empty input")
	}
	if isRosetta {
		t.Error("expected no Rosetta on empty input")
	}
}

func TestParseRosettaStatus_M1Ultra(t *testing.T) {
	isAppleSilicon, isRosetta := parseRosettaStatus("0\n", "Apple M1 Ultra\n")
	if !isAppleSilicon {
		t.Error("expected Apple Silicon for M1 Ultra")
	}
	if isRosetta {
		t.Error("expected native (not Rosetta) for proc_translated=0")
	}
}

func TestParseRosettaStatus_M3Max(t *testing.T) {
	isAppleSilicon, _ := parseRosettaStatus("0\n", "Apple M3 Max\n")
	if !isAppleSilicon {
		t.Error("expected Apple Silicon for M3 Max")
	}
}

// --- parseSecureBootStatus tests ---

func TestParseSecureBootStatus_Enabled(t *testing.T) {
	result := parseSecureBootStatus("Authenticated Root status: enabled\n")
	if result != "enabled" {
		t.Errorf("expected 'enabled', got %q", result)
	}
}

func TestParseSecureBootStatus_Disabled(t *testing.T) {
	result := parseSecureBootStatus("Authenticated Root status: disabled\n")
	if result != "disabled" {
		t.Errorf("expected 'disabled', got %q", result)
	}
}

func TestParseSecureBootStatus_FullSecurity(t *testing.T) {
	result := parseSecureBootStatus("%02")
	if result != "full security" {
		t.Errorf("expected 'full security', got %q", result)
	}
}

func TestParseSecureBootStatus_MediumSecurity(t *testing.T) {
	result := parseSecureBootStatus("%01")
	if result != "medium security" {
		t.Errorf("expected 'medium security', got %q", result)
	}
}

func TestParseSecureBootStatus_NoSecurity(t *testing.T) {
	result := parseSecureBootStatus("%00")
	if result != "no security" {
		t.Errorf("expected 'no security', got %q", result)
	}
}

func TestParseSecureBootStatus_Empty(t *testing.T) {
	result := parseSecureBootStatus("")
	if result != "unknown" {
		t.Errorf("expected 'unknown', got %q", result)
	}
}

// --- parseIoregModelID tests ---

func TestParseIoregModelID_Standard(t *testing.T) {
	output := `+-o Root
    {
      "model" = <"Mac14,2">
      "board-id" = <"Mac-AA95B1DDAB278B95">
    }`
	model := parseIoregModelID(output)
	if model != "Mac14,2" {
		t.Errorf("expected 'Mac14,2', got %q", model)
	}
}

func TestParseIoregModelID_MacStudio(t *testing.T) {
	output := `    "model" = <"Mac13,1">`
	model := parseIoregModelID(output)
	if model != "Mac13,1" {
		t.Errorf("expected 'Mac13,1', got %q", model)
	}
}

func TestParseIoregModelID_NoModel(t *testing.T) {
	output := `    "board-id" = <"Mac-AA95B1DDAB278B95">`
	model := parseIoregModelID(output)
	if model != "" {
		t.Errorf("expected empty string, got %q", model)
	}
}

func TestParseIoregModelID_EmptyOutput(t *testing.T) {
	model := parseIoregModelID("")
	if model != "" {
		t.Errorf("expected empty string, got %q", model)
	}
}

// --- parseSystemVersionPlist tests ---

func TestParseSystemVersionPlist_Standard(t *testing.T) {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>ProductBuildVersion</key>
	<string>25D125</string>
	<key>ProductName</key>
	<string>macOS</string>
	<key>ProductUserVisibleVersion</key>
	<string>26.3</string>
	<key>ProductVersion</key>
	<string>26.3</string>
</dict>
</plist>`
	ver := parseSystemVersionPlist(plist)
	if ver.ProductName != "macOS" {
		t.Errorf("ProductName = %q, want 'macOS'", ver.ProductName)
	}
	if ver.ProductVersion != "26.3" {
		t.Errorf("ProductVersion = %q, want '26.3'", ver.ProductVersion)
	}
	if ver.ProductBuildVersion != "25D125" {
		t.Errorf("ProductBuildVersion = %q, want '25D125'", ver.ProductBuildVersion)
	}
}

func TestParseSystemVersionPlist_Ventura(t *testing.T) {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>ProductBuildVersion</key>
	<string>22A380</string>
	<key>ProductName</key>
	<string>macOS</string>
	<key>ProductVersion</key>
	<string>13.0</string>
</dict>
</plist>`
	ver := parseSystemVersionPlist(plist)
	if ver.ProductName != "macOS" {
		t.Errorf("ProductName = %q, want 'macOS'", ver.ProductName)
	}
	if ver.ProductVersion != "13.0" {
		t.Errorf("ProductVersion = %q, want '13.0'", ver.ProductVersion)
	}
	if ver.ProductBuildVersion != "22A380" {
		t.Errorf("ProductBuildVersion = %q, want '22A380'", ver.ProductBuildVersion)
	}
}

func TestParseSystemVersionPlist_Empty(t *testing.T) {
	ver := parseSystemVersionPlist("")
	if ver.ProductName != "" || ver.ProductVersion != "" || ver.ProductBuildVersion != "" {
		t.Error("expected all empty fields for empty input")
	}
}

func TestParseSystemVersionPlist_MissingKeys(t *testing.T) {
	plist := `<?xml version="1.0"?>
<plist version="1.0">
<dict>
	<key>ProductName</key>
	<string>macOS</string>
</dict>
</plist>`
	ver := parseSystemVersionPlist(plist)
	if ver.ProductName != "macOS" {
		t.Errorf("ProductName = %q, want 'macOS'", ver.ProductName)
	}
	if ver.ProductVersion != "" {
		t.Errorf("ProductVersion should be empty, got %q", ver.ProductVersion)
	}
	if ver.ProductBuildVersion != "" {
		t.Errorf("ProductBuildVersion should be empty, got %q", ver.ProductBuildVersion)
	}
}

func TestParseSystemVersionPlist_InvalidXML(t *testing.T) {
	ver := parseSystemVersionPlist("this is not xml")
	if ver.ProductName != "" {
		t.Errorf("expected empty ProductName for invalid XML, got %q", ver.ProductName)
	}
}

func TestParseSystemVersionPlist_MacOSX(t *testing.T) {
	// Older macOS versions used "Mac OS X" as ProductName
	plist := `<?xml version="1.0"?>
<plist version="1.0">
<dict>
	<key>ProductName</key>
	<string>Mac OS X</string>
	<key>ProductVersion</key>
	<string>10.15.7</string>
	<key>ProductBuildVersion</key>
	<string>19H1922</string>
</dict>
</plist>`
	ver := parseSystemVersionPlist(plist)
	if ver.ProductName != "Mac OS X" {
		t.Errorf("ProductName = %q, want 'Mac OS X'", ver.ProductName)
	}
	if ver.ProductVersion != "10.15.7" {
		t.Errorf("ProductVersion = %q, want '10.15.7'", ver.ProductVersion)
	}
}
