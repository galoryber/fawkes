package commands

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"runtime"
	"strings"

	"fawkes/pkg/structs"

	_ "modernc.org/sqlite"
)

// PkgListCommand lists installed packages/software.
type PkgListCommand struct{}

func (c *PkgListCommand) Name() string        { return "pkg-list" }
func (c *PkgListCommand) Description() string { return "List installed packages and software" }

func (c *PkgListCommand) Execute(task structs.Task) structs.CommandResult {
	var output string

	switch runtime.GOOS {
	case "linux":
		output = pkgListLinux()
	case "darwin":
		output = pkgListDarwin()
	case "windows":
		output = pkgListWindows()
	default:
		output = fmt.Sprintf("Unsupported platform: %s", runtime.GOOS)
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func pkgListLinux() string {
	var sb strings.Builder
	sb.WriteString("[*] Installed Packages (Linux)\n\n")

	found := false

	// Try dpkg (Debian/Ubuntu) — native file parsing first, then subprocess fallback
	if pkgs := parseDpkgStatus(); len(pkgs) > 0 {
		sb.WriteString(fmt.Sprintf("  Package Manager: dpkg (%d installed)\n", len(pkgs)))
		for i, pkg := range pkgs {
			sb.WriteString(fmt.Sprintf("    %-40s %s\n", pkg[0], pkg[1]))
			if i >= 99 {
				sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(pkgs)-100))
				break
			}
		}
		found = true
	} else if output := runQuietCommand("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Status}\n"); output != "" {
		lines := strings.Split(strings.TrimSpace(output), "\n")
		installed := 0
		for _, line := range lines {
			if strings.Contains(line, "install ok installed") {
				installed++
			}
		}
		sb.WriteString(fmt.Sprintf("  Package Manager: dpkg (%d installed)\n", installed))
		count := 0
		for _, line := range lines {
			if !strings.Contains(line, "install ok installed") {
				continue
			}
			parts := strings.SplitN(line, "\t", 3)
			if len(parts) >= 2 {
				sb.WriteString(fmt.Sprintf("    %-40s %s\n", parts[0], parts[1]))
			}
			count++
			if count >= 100 {
				sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", installed-100))
				break
			}
		}
		found = true
	}

	// Try rpm (RHEL/CentOS/Fedora) — native SQLite first, then subprocess fallback
	if !found {
		if pkgs := parseRpmDB(); len(pkgs) > 0 {
			sb.WriteString(fmt.Sprintf("  Package Manager: rpm (%d installed)\n", len(pkgs)))
			for i, pkg := range pkgs {
				sb.WriteString(fmt.Sprintf("    %-40s %s\n", pkg[0], pkg[1]))
				if i >= 99 {
					sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(pkgs)-100))
					break
				}
			}
			found = true
		} else if output := runQuietCommand("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"); output != "" {
			lines := strings.Split(strings.TrimSpace(output), "\n")
			sb.WriteString(fmt.Sprintf("  Package Manager: rpm (%d installed)\n", len(lines)))
			for i, line := range lines {
				parts := strings.SplitN(line, "\t", 2)
				if len(parts) >= 2 {
					sb.WriteString(fmt.Sprintf("    %-40s %s\n", parts[0], parts[1]))
				}
				if i >= 99 {
					sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(lines)-100))
					break
				}
			}
			found = true
		}
	}

	// Try apk (Alpine) — native file parsing first, then subprocess fallback
	if !found {
		if pkgs := parseApkInstalled(); len(pkgs) > 0 {
			sb.WriteString(fmt.Sprintf("  Package Manager: apk (%d installed)\n", len(pkgs)))
			for i, pkg := range pkgs {
				sb.WriteString(fmt.Sprintf("    %-40s %s\n", pkg[0], pkg[1]))
				if i >= 99 {
					sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(pkgs)-100))
					break
				}
			}
			found = true
		} else if output := runQuietCommand("apk", "list", "--installed"); output != "" {
			lines := strings.Split(strings.TrimSpace(output), "\n")
			sb.WriteString(fmt.Sprintf("  Package Manager: apk (%d installed)\n", len(lines)))
			for i, line := range lines {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
				if i >= 99 {
					sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(lines)-100))
					break
				}
			}
			found = true
		}
	}

	// Try snap
	snapOutput := runQuietCommand("snap", "list")
	if snapOutput != "" {
		lines := strings.Split(strings.TrimSpace(snapOutput), "\n")
		if len(lines) > 1 {
			sb.WriteString(fmt.Sprintf("\n  Snap packages: %d\n", len(lines)-1))
			for _, line := range lines {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
	}

	// Try flatpak
	flatpakOutput := runQuietCommand("flatpak", "list", "--columns=application,version")
	if flatpakOutput != "" {
		lines := strings.Split(strings.TrimSpace(flatpakOutput), "\n")
		if len(lines) > 0 {
			sb.WriteString(fmt.Sprintf("\n  Flatpak apps: %d\n", len(lines)))
			for _, line := range lines {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
	}

	if !found && snapOutput == "" && flatpakOutput == "" {
		sb.WriteString("  No supported package manager found (tried: dpkg, rpm, apk)\n")
	}

	return sb.String()
}

func pkgListDarwin() string {
	var sb strings.Builder
	sb.WriteString("[*] Installed Software (macOS)\n\n")

	// Homebrew
	brewOutput := runQuietCommand("brew", "list", "--versions")
	if brewOutput != "" {
		lines := strings.Split(strings.TrimSpace(brewOutput), "\n")
		sb.WriteString(fmt.Sprintf("  Homebrew packages: %d\n", len(lines)))
		for i, line := range lines {
			sb.WriteString(fmt.Sprintf("    %s\n", line))
			if i >= 99 {
				sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(lines)-100))
				break
			}
		}
	} else {
		sb.WriteString("  Homebrew: not installed\n")
	}

	// Homebrew casks
	caskOutput := runQuietCommand("brew", "list", "--cask", "--versions")
	if caskOutput != "" {
		lines := strings.Split(strings.TrimSpace(caskOutput), "\n")
		sb.WriteString(fmt.Sprintf("\n  Homebrew casks: %d\n", len(lines)))
		for i, line := range lines {
			sb.WriteString(fmt.Sprintf("    %s\n", line))
			if i >= 99 {
				sb.WriteString(fmt.Sprintf("    ... and %d more\n", len(lines)-100))
				break
			}
		}
	}

	// Applications directory
	sb.WriteString("\n  /Applications:\n")
	entries, err := os.ReadDir("/Applications")
	if err == nil {
		count := 0
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".app") {
				sb.WriteString(fmt.Sprintf("    %s\n", entry.Name()))
				count++
			}
		}
		sb.WriteString(fmt.Sprintf("  Total .app bundles: %d\n", count))
	}

	return sb.String()
}

func pkgListWindows() string {
	var sb strings.Builder
	sb.WriteString("[*] Installed Software (Windows)\n\n")

	// Try native registry reading first (no subprocess spawned)
	if native := pkgListWindowsNative(); native != "" {
		sb.WriteString(native)
		return sb.String()
	}

	// Fall back to PowerShell
	psCmd := "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Sort-Object DisplayName | ForEach-Object { \"$($_.DisplayName)\t$($_.DisplayVersion)\" }"
	output := runQuietCommand("powershell", BuildPSArgs(psCmd, InternalPSOptions())...)
	if output != "" {
		lines := strings.Split(strings.TrimSpace(output), "\n")
		sb.WriteString(fmt.Sprintf("  Installed programs: %d\n\n", len(lines)))
		sb.WriteString(fmt.Sprintf("  %-55s %s\n", "Name", "Version"))
		sb.WriteString("  " + strings.Repeat("-", 70) + "\n")
		for i, line := range lines {
			parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
			if len(parts) == 2 {
				sb.WriteString(fmt.Sprintf("  %-55s %s\n", parts[0], parts[1]))
			} else {
				sb.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(line)))
			}
			if i >= 199 {
				sb.WriteString(fmt.Sprintf("  ... and %d more (showing first 200)\n", len(lines)-200))
				break
			}
		}
	} else {
		sb.WriteString("  Failed to enumerate installed programs\n")
	}

	return sb.String()
}

// parseDpkgStatus reads /var/lib/dpkg/status directly to enumerate installed packages.
// Returns [name, version] pairs for packages with Status: install ok installed.
func parseDpkgStatus() [][2]string {
	f, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return nil
	}
	defer f.Close()

	var pkgs [][2]string
	var name, version, status string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// End of package block
			if name != "" && status == "install ok installed" {
				pkgs = append(pkgs, [2]string{name, version})
			}
			name, version, status = "", "", ""
			continue
		}
		if strings.HasPrefix(line, "Package: ") {
			name = line[9:]
		} else if strings.HasPrefix(line, "Version: ") {
			version = line[9:]
		} else if strings.HasPrefix(line, "Status: ") {
			status = line[8:]
		}
	}
	// Handle last block if file doesn't end with blank line
	if name != "" && status == "install ok installed" {
		pkgs = append(pkgs, [2]string{name, version})
	}
	return pkgs
}

// parseApkInstalled reads /lib/apk/db/installed directly to enumerate Alpine packages.
// The file uses a simple record format: blank-line-separated blocks with "P:" (name),
// "V:" (version) fields. No subprocess spawned.
func parseApkInstalled() [][2]string {
	f, err := os.Open("/lib/apk/db/installed")
	if err != nil {
		return nil
	}
	defer f.Close()

	var pkgs [][2]string
	var name, version string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if name != "" {
				pkgs = append(pkgs, [2]string{name, version})
			}
			name, version = "", ""
			continue
		}
		if strings.HasPrefix(line, "P:") {
			name = line[2:]
		} else if strings.HasPrefix(line, "V:") {
			version = line[2:]
		}
	}
	if name != "" {
		pkgs = append(pkgs, [2]string{name, version})
	}
	return pkgs
}

// parseRpmDB reads the RPM database directly via SQLite.
// RHEL 8+/Fedora 33+ use /var/lib/rpm/rpmdb.sqlite (SQLite).
// Older systems use BDB at /var/lib/rpm/Packages (not supported here).
// No subprocess spawned.
func parseRpmDB() [][2]string {
	dbPath := "/var/lib/rpm/rpmdb.sqlite"
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT blob FROM Packages")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var pkgs [][2]string
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			continue
		}
		name, version := rpmParseHeaderBlob(blob)
		if name != "" {
			pkgs = append(pkgs, [2]string{name, version})
		}
	}
	return pkgs
}

// rpmParseHeaderBlob extracts Name and Version from an RPM header blob.
// RPM header format: 4-byte magic (8eade801), 4-byte padding, 4-byte nindex (BE),
// 4-byte hsize (BE), then nindex index entries (16 bytes each: tag, type, offset, count),
// then hsize bytes of data store. Tag 1000 = Name, Tag 1001 = Version, Tag 1002 = Release.
func rpmParseHeaderBlob(blob []byte) (string, string) {
	if len(blob) < 16 {
		return "", ""
	}

	// Skip to find the header magic 0x8eade801
	off := 0
	for off+16 <= len(blob) {
		if blob[off] == 0x8e && blob[off+1] == 0xad && blob[off+2] == 0xe8 && blob[off+3] == 0x01 {
			break
		}
		off++
	}
	if off+16 > len(blob) {
		return "", ""
	}

	// Parse header intro
	off += 4 // skip magic
	off += 4 // skip reserved/padding
	nindex := beUint32(blob, off)
	off += 4
	hsize := beUint32(blob, off)
	off += 4

	if nindex > 10000 || hsize > 10*1024*1024 {
		return "", "" // sanity check
	}

	indexEnd := off + int(nindex)*16
	if indexEnd+int(hsize) > len(blob) {
		return "", ""
	}

	dataStore := blob[indexEnd : indexEnd+int(hsize)]

	var name, version, release string

	for i := 0; i < int(nindex); i++ {
		entryOff := off + i*16
		tag := beUint32(blob, entryOff)
		// typ := beUint32(blob, entryOff+4)  // unused
		dataOff := beUint32(blob, entryOff+8)
		// count := beUint32(blob, entryOff+12) // unused

		if int(dataOff) >= len(dataStore) {
			continue
		}

		switch tag {
		case 1000: // RPMTAG_NAME
			name = cStringAt(dataStore, int(dataOff))
		case 1001: // RPMTAG_VERSION
			version = cStringAt(dataStore, int(dataOff))
		case 1002: // RPMTAG_RELEASE
			release = cStringAt(dataStore, int(dataOff))
		}
	}

	ver := version
	if release != "" {
		ver = version + "-" + release
	}
	return name, ver
}

// beUint32 reads a big-endian uint32 from a byte slice at the given offset.
func beUint32(b []byte, off int) uint32 {
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3])
}

// cStringAt reads a null-terminated string from a byte slice at the given offset.
func cStringAt(b []byte, off int) string {
	end := off
	for end < len(b) && b[end] != 0 {
		end++
	}
	return string(b[off:end])
}

// runQuietCommand runs a command with a timeout and returns stdout, or empty string on error.
func runQuietCommand(name string, args ...string) string {
	out, err := execCmdTimeoutOutput(name, args...)
	if err != nil {
		return ""
	}
	return string(out)
}
