package commands

import (
	"bufio"
	"database/sql"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

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
	_ = rows.Err() // best-effort; return partial results on iteration error
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
