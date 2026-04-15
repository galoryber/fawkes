//go:build darwin

package commands

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	_ "modernc.org/sqlite"
)

// macPrivescCheckTCC inspects TCC database for permission grants
func macPrivescCheckTCC() structs.CommandResult {
	var sb strings.Builder

	homeDir, _ := os.UserHomeDir()

	// TCC databases
	tccPaths := []struct {
		path string
		desc string
	}{
		{"/Library/Application Support/com.apple.TCC/TCC.db", "System TCC (root-managed)"},
	}
	if homeDir != "" {
		tccPaths = append(tccPaths, struct {
			path string
			desc string
		}{filepath.Join(homeDir, "Library/Application Support/com.apple.TCC/TCC.db"), "User TCC"})
	}

	for _, tcc := range tccPaths {
		info, err := os.Stat(tcc.path)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s: not accessible\n", tcc.desc))
			continue
		}
		sb.WriteString(fmt.Sprintf("%s: %s (%s)\n", tcc.desc, tcc.path, info.Mode().String()))

		// Query TCC database using in-process SQLite (no child process)
		db, err := sql.Open("sqlite", tcc.path+"?mode=ro")
		if err != nil {
			sb.WriteString(fmt.Sprintf("  Cannot open database: %v\n", err))
			continue
		}
		rows, err := db.Query("SELECT service, client, auth_value, auth_reason FROM access WHERE auth_value > 0 ORDER BY service")
		if err != nil {
			db.Close()
			sb.WriteString(fmt.Sprintf("  Cannot query (expected if not root): %v\n", err))
			continue
		}

		interesting := 0
		rowCount := 0
		for rows.Next() {
			var service, client string
			var authVal, authReason int
			if err := rows.Scan(&service, &client, &authVal, &authReason); err != nil {
				continue
			}
			rowCount++
			flag := macTCCServiceFlag(service)
			sb.WriteString(fmt.Sprintf("  %s → %s (auth=%d)%s\n", service, client, authVal, flag))
			if flag != "" {
				interesting++
			}
		}
		if err := rows.Err(); err != nil {
			sb.WriteString(fmt.Sprintf("  Row iteration error: %v\n", err))
		}
		rows.Close()
		db.Close()

		if rowCount == 0 {
			sb.WriteString("  No granted permissions found.\n")
		}
		if interesting > 0 {
			sb.WriteString(fmt.Sprintf("  [*] %d high-value permission grants found\n", interesting))
		}
	}

	return successResult(sb.String())
}

// macPrivescCheckDylib checks for dylib hijacking opportunities
func macPrivescCheckDylib() structs.CommandResult {
	var sb strings.Builder

	// Check DYLD_* environment variables
	dyldVars := []string{"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"DYLD_FALLBACK_LIBRARY_PATH", "DYLD_FORCE_FLAT_NAMESPACE"}

	for _, env := range dyldVars {
		if val := os.Getenv(env); val != "" {
			sb.WriteString(fmt.Sprintf("[!] %s=%s\n", env, val))
		}
	}

	// Check if Hardened Runtime is common (look at a few key binaries)
	binaries := []string{"/usr/bin/ssh", "/usr/bin/sudo", "/usr/bin/login"}
	for _, bin := range binaries {
		out, err := execCmdTimeout("codesign", "-dv", bin)
		if err == nil {
			output := string(out)
			if strings.Contains(output, "runtime") {
				sb.WriteString(fmt.Sprintf("  %s: Hardened Runtime (DYLD injection blocked)\n", bin))
			} else {
				sb.WriteString(fmt.Sprintf("  [!] %s: NO Hardened Runtime (DYLD injection possible)\n", bin))
			}
		}
	}

	// Check for writable directories in common library paths
	libPaths := []string{"/usr/local/lib", "/opt/homebrew/lib", "/Library/Frameworks"}
	for _, p := range libPaths {
		if macIsWritable(p) {
			sb.WriteString(fmt.Sprintf("[!] %s is WRITABLE — dylib planting possible\n", p))
		}
	}

	// Check for unsigned or ad-hoc signed applications
	appDirs := []string{"/Applications"}
	for _, dir := range appDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var unsigned []string
		count := 0
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".app") {
				continue
			}
			count++
			appPath := filepath.Join(dir, entry.Name())
			out, err := execCmdTimeout("codesign", "-v", appPath)
			if err != nil {
				output := string(out)
				if strings.Contains(output, "not signed") || strings.Contains(output, "invalid signature") {
					unsigned = append(unsigned, fmt.Sprintf("  [!] %s", appPath))
				}
			}
			if count >= 20 { // Limit to avoid slow scans
				break
			}
		}
		if len(unsigned) > 0 {
			sb.WriteString(fmt.Sprintf("\nUnsigned/invalid apps in %s (%d):\n", dir, len(unsigned)))
			sb.WriteString(strings.Join(unsigned, "\n") + "\n")
		}
	}

	if sb.Len() == 0 {
		sb.WriteString("No obvious dylib hijacking vectors found.\n")
	}

	return successResult(sb.String())
}

// macPrivescCheckWritable checks for writable sensitive paths
func macPrivescCheckWritable() structs.CommandResult {
	var sb strings.Builder

	// Check PATH directories for write access
	pathDirs := strings.Split(os.Getenv("PATH"), ":")
	var writablePATH []string
	for _, dir := range pathDirs {
		if dir == "" {
			continue
		}
		if macIsWritable(dir) {
			writablePATH = append(writablePATH, "  "+dir)
		}
	}

	sb.WriteString(fmt.Sprintf("Writable PATH directories (%d):\n", len(writablePATH)))
	if len(writablePATH) > 0 {
		sb.WriteString(strings.Join(writablePATH, "\n") + "\n")
		sb.WriteString("[!] Writable PATH directories enable binary hijacking\n")
	} else {
		sb.WriteString("  (none — PATH is clean)\n")
	}

	// Sensitive macOS paths
	sensitiveFiles := map[string]string{
		"/etc/passwd":                            "User database",
		"/etc/sudoers":                           "Sudo configuration",
		"/etc/authorization":                     "Authorization policy",
		"/private/etc/pam.d":                     "PAM configuration",
		"/Library/Preferences":                   "System preferences",
		"/Library/Security/SecurityAgentPlugins": "Security agent plugins (root)",
	}

	var writable, readable []string
	for path, desc := range sensitiveFiles {
		if macIsWritable(path) {
			info, _ := os.Stat(path)
			mode := "?"
			if info != nil {
				mode = info.Mode().String()
			}
			writable = append(writable, fmt.Sprintf("  %s — %s (%s)", path, desc, mode))
		} else if path == "/etc/sudoers" || path == "/etc/authorization" {
			if f, err := os.Open(path); err == nil {
				f.Close()
				info, _ := os.Stat(path)
				mode := "?"
				if info != nil {
					mode = info.Mode().String()
				}
				readable = append(readable, fmt.Sprintf("  %s — %s (%s)", path, desc, mode))
			}
		}
	}

	if len(writable) > 0 {
		sb.WriteString(fmt.Sprintf("\n[!] WRITABLE sensitive paths (%d):\n", len(writable)))
		sb.WriteString(strings.Join(writable, "\n") + "\n")
	}
	if len(readable) > 0 {
		sb.WriteString(fmt.Sprintf("\nReadable sensitive files (%d):\n", len(readable)))
		sb.WriteString(strings.Join(readable, "\n") + "\n")
	}

	return successResult(sb.String())
}
