package commands

import (
	"encoding/xml"
	"strings"
)

// systemVersionPlist represents the parsed SystemVersion.plist content.
type systemVersionPlist struct {
	ProductName         string
	ProductVersion      string
	ProductBuildVersion string
}

// parseSystemVersionPlist extracts version info from the XML plist content of
// /System/Library/CoreServices/SystemVersion.plist. This avoids spawning sw_vers.
func parseSystemVersionPlist(xmlContent string) systemVersionPlist {
	var result systemVersionPlist

	// Apple plists use <dict> with alternating <key> and <string> elements.
	// Parse the XML to extract key-value pairs.
	decoder := xml.NewDecoder(strings.NewReader(xmlContent))
	var currentKey string
	var inKey, inString bool

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "key":
				inKey = true
			case "string":
				inString = true
			}
		case xml.EndElement:
			inKey = false
			inString = false
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text == "" {
				continue
			}
			if inKey {
				currentKey = text
			} else if inString {
				switch currentKey {
				case "ProductName":
					result.ProductName = text
				case "ProductVersion", "ProductUserVisibleVersion":
					if result.ProductVersion == "" {
						result.ProductVersion = text
					}
				case "ProductBuildVersion":
					result.ProductBuildVersion = text
				}
			}
		}
	}

	return result
}

// parseIoregSerial extracts the IOPlatformSerialNumber from ioreg output.
// Input: output of `ioreg -rd1 -c IOPlatformExpertDevice`
func parseIoregSerial(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "IOPlatformSerialNumber") {
			// Format: "IOPlatformSerialNumber" = "XXXXXXXXXXXXX"
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.Trim(strings.TrimSpace(parts[1]), "\"")
			}
		}
	}
	return ""
}

// parseSpctlStatus parses Gatekeeper status from spctl --status output.
// Returns "enabled", "disabled", or the raw output.
func parseSpctlStatus(output string) string {
	output = strings.TrimSpace(output)
	if strings.Contains(output, "assessments enabled") {
		return "enabled"
	}
	if strings.Contains(output, "assessments disabled") {
		return "disabled"
	}
	if output == "" {
		return "unknown"
	}
	return output
}

// parseFdesetupStatus parses FileVault status from fdesetup status output.
// Returns "on", "off", "encrypting", "decrypting", or the raw output.
func parseFdesetupStatus(output string) string {
	output = strings.TrimSpace(output)
	lower := strings.ToLower(output)
	if strings.Contains(lower, "filevault is on") {
		return "on"
	}
	if strings.Contains(lower, "filevault is off") {
		return "off"
	}
	if strings.Contains(lower, "encryption in progress") {
		return "encrypting"
	}
	if strings.Contains(lower, "decryption in progress") {
		return "decrypting"
	}
	if output == "" {
		return "unknown"
	}
	return output
}

// parseMDMEnrollment parses MDM enrollment status from `profiles status -type enrollment` output.
// Returns a struct with enrollment details.
type mdmEnrollmentInfo struct {
	Enrolled    bool
	MDMEnrolled bool
	DEPEnrolled bool
	RawOutput   string
}

func parseMDMEnrollment(output string) mdmEnrollmentInfo {
	info := mdmEnrollmentInfo{RawOutput: strings.TrimSpace(output)}
	lower := strings.ToLower(output)

	// Check MDM enrollment
	if strings.Contains(lower, "mdm enrollment: yes") {
		info.MDMEnrolled = true
		info.Enrolled = true
	}

	// Check DEP enrollment
	if strings.Contains(lower, "dep enrollment: yes") ||
		strings.Contains(lower, "enrolled via dep: yes") {
		info.DEPEnrolled = true
		info.Enrolled = true
	}

	// Generic enrollment check
	if strings.Contains(lower, "enrolled: yes") {
		info.Enrolled = true
	}

	return info
}

// parseRosettaStatus determines Apple Silicon/Rosetta 2 status.
// procTranslated: output of `sysctl -n sysctl.proc_translated` ("0" or "1")
// cpuBrand: output of `sysctl -n machdep.cpu.brand_string`
func parseRosettaStatus(procTranslated, cpuBrand string) (isAppleSilicon bool, isRosetta bool) {
	cpuBrand = strings.TrimSpace(cpuBrand)
	procTranslated = strings.TrimSpace(procTranslated)

	// Apple Silicon CPUs contain "Apple" in the brand string
	if strings.Contains(cpuBrand, "Apple") {
		isAppleSilicon = true
	}

	// proc_translated = 1 means running under Rosetta 2
	if procTranslated == "1" {
		isRosetta = true
	}

	return
}

// parseSecureBootStatus parses Secure Boot status from `csrutil authenticated-root status` output.
// Also handles `nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy` output.
func parseSecureBootStatus(output string) string {
	output = strings.TrimSpace(output)
	lower := strings.ToLower(output)
	if strings.Contains(lower, "enabled") {
		return "enabled"
	}
	if strings.Contains(lower, "disabled") {
		return "disabled"
	}
	// Check for Apple Secure Boot policy values
	if strings.Contains(output, "%02") {
		return "full security"
	}
	if strings.Contains(output, "%01") {
		return "medium security"
	}
	if strings.Contains(output, "%00") {
		return "no security"
	}
	if output == "" {
		return "unknown"
	}
	return output
}

// parseIoregModelID extracts the model identifier from ioreg output.
// More specific than hw.model — gives exact model (e.g., "Mac14,2" vs "Mac14,2").
func parseIoregModelID(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "\"model\"") && strings.Contains(line, "<") {
			// Format: "model" = <"Mac14,2">
			start := strings.Index(line, "<\"")
			end := strings.Index(line, "\">")
			if start >= 0 && end > start {
				return line[start+2 : end]
			}
			// Alternative format without quotes inside brackets
			start = strings.Index(line, "<")
			end = strings.Index(line, ">")
			if start >= 0 && end > start {
				return strings.Trim(line[start+1:end], "\"")
			}
		}
	}
	return ""
}
