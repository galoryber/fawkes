package http

// http_headers.go contains browser-realistic HTTP header generation helpers.
// These functions parse the User-Agent string to generate matching sec-ch-ua
// client hint headers, ensuring C2 traffic passes JA4H fingerprint analysis.

import (
	"fmt"
	"strconv"
	"strings"
)

// extractChromeVersion extracts the Chrome major version from a User-Agent string.
// Returns empty string if no Chrome version is found.
func extractChromeVersion(ua string) string {
	idx := strings.Index(ua, "Chrome/")
	if idx == -1 {
		return ""
	}
	rest := ua[idx+7:]
	dotIdx := strings.Index(rest, ".")
	if dotIdx == -1 {
		// No dot — try to use the whole remaining token
		spIdx := strings.Index(rest, " ")
		if spIdx == -1 {
			return rest
		}
		return rest[:spIdx]
	}
	return rest[:dotIdx]
}

// extractPlatform extracts the OS platform from a User-Agent string.
// Returns "Windows", "macOS", or "Linux". Defaults to "Windows".
func extractPlatform(ua string) string {
	switch {
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS"):
		return "macOS"
	case strings.Contains(ua, "Linux") && !strings.Contains(ua, "Android"):
		return "Linux"
	default:
		return "Windows"
	}
}

// greaseBrand generates the GREASE (Generate Random Extensions And Sustain Extensibility)
// "Not A Brand" string that Chrome includes in sec-ch-ua. The format rotates across
// Chrome major versions to prevent fingerprinting on the GREASE value itself.
func greaseBrand(majorVersion string) string {
	ver, err := strconv.Atoi(majorVersion)
	if err != nil {
		return `"Not_A Brand";v="8"`
	}
	// Chrome rotates GREASE brands roughly every 10 versions.
	// These match observed Chrome behavior from version 110+.
	switch {
	case ver >= 130:
		return `"Not/A)Brand";v="8"`
	case ver >= 120:
		return `"Not_A Brand";v="8"`
	case ver >= 110:
		return `"Not/A)Brand";v="99"`
	default:
		return `"Not_A Brand";v="99"`
	}
}

// generateSecChUa generates the sec-ch-ua header value matching a Chrome User-Agent.
// Returns empty string if the UA doesn't contain a Chrome version.
// Example output: "Chromium";v="134", "Not/A)Brand";v="8", "Google Chrome";v="134"
func generateSecChUa(ua string) string {
	version := extractChromeVersion(ua)
	if version == "" {
		return ""
	}
	return fmt.Sprintf(`"Chromium";v="%s", %s, "Google Chrome";v="%s"`, version, greaseBrand(version), version)
}

// generateSecChUaMobile returns "?0" for desktop User-Agents and "?1" for mobile.
func generateSecChUaMobile(ua string) string {
	if strings.Contains(ua, "Mobile") || strings.Contains(ua, "Android") {
		return "?1"
	}
	return "?0"
}

// generateSecChUaPlatform generates the sec-ch-ua-platform header value.
// Example output: "Windows"
func generateSecChUaPlatform(ua string) string {
	return fmt.Sprintf(`"%s"`, extractPlatform(ua))
}

// chromeAcceptHeader returns the Accept header value matching modern Chrome.
// Chrome includes image format preferences that differ from other browsers.
const chromeAcceptHeader = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"

// chromeAcceptEncoding includes Brotli (br) which all modern browsers support since 2017.
// Missing br in Accept-Encoding is a strong signal of non-browser traffic.
const chromeAcceptEncoding = "gzip, deflate, br"
