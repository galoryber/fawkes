package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPkgListName(t *testing.T) {
	cmd := &PkgListCommand{}
	if cmd.Name() != "pkg-list" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "pkg-list")
	}
}

func TestPkgListDescription(t *testing.T) {
	cmd := &PkgListCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestPkgListExecute(t *testing.T) {
	cmd := &PkgListCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !result.Completed {
		t.Error("Completed should be true")
	}
	if !strings.Contains(result.Output, "Installed") {
		t.Error("Output should contain 'Installed'")
	}
}

func TestPkgListExecuteWithFilter(t *testing.T) {
	cmd := &PkgListCommand{}
	result := cmd.Execute(structs.Task{Params: `{"filter":"nonexistent_pkg_xyz"}`})
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	// With a filter that matches nothing, the output should still succeed
	if !result.Completed {
		t.Error("Completed should be true")
	}
}

func TestPkgMatchesFilter(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		want   bool
	}{
		{"bash", "", true},          // empty filter matches all
		{"bash", "bash", true},      // exact match
		{"libbash", "bash", true},   // substring
		{"BASH", "bash", true},      // case-insensitive
		{"curl", "bash", false},     // no match
		{"OpenSSH", "ssh", true},    // partial match
	}
	for _, tt := range tests {
		got := pkgMatchesFilter(tt.name, tt.filter)
		if got != tt.want {
			t.Errorf("pkgMatchesFilter(%q, %q) = %v, want %v", tt.name, tt.filter, got, tt.want)
		}
	}
}

func TestFilterPkgPairs(t *testing.T) {
	pkgs := [][2]string{
		{"bash", "5.1"},
		{"curl", "7.88"},
		{"libbash-dev", "5.1"},
		{"zlib", "1.2.13"},
	}

	// No filter returns all
	result := filterPkgPairs(pkgs, "")
	if len(result) != 4 {
		t.Errorf("no filter: got %d, want 4", len(result))
	}

	// Filter "bash" matches 2
	result = filterPkgPairs(pkgs, "bash")
	if len(result) != 2 {
		t.Errorf("filter 'bash': got %d, want 2", len(result))
	}

	// Filter with no matches
	result = filterPkgPairs(pkgs, "nonexistent")
	if len(result) != 0 {
		t.Errorf("filter 'nonexistent': got %d, want 0", len(result))
	}
}

func TestRunQuietCommand(t *testing.T) {
	// Test with a command that exists
	output := runQuietCommand("echo", "hello")
	if !strings.Contains(output, "hello") {
		t.Errorf("runQuietCommand('echo hello') = %q, want to contain 'hello'", output)
	}
}

func TestRunQuietCommandFailure(t *testing.T) {
	// Test with a nonexistent command
	output := runQuietCommand("nonexistent_command_xyz")
	if output != "" {
		t.Errorf("runQuietCommand for nonexistent command should return empty, got %q", output)
	}
}

func TestParseDpkgStatus(t *testing.T) {
	// parseDpkgStatus reads from /var/lib/dpkg/status
	// On dpkg-based systems (CI Ubuntu), returns installed packages
	// On non-dpkg systems, returns nil — both are acceptable
	pkgs := parseDpkgStatus()
	for _, pkg := range pkgs {
		if pkg[0] == "" {
			t.Error("package name should not be empty")
		}
		if pkg[1] == "" {
			t.Error("package version should not be empty")
		}
	}
}

func TestParseApkInstalled(t *testing.T) {
	// parseApkInstalled reads /lib/apk/db/installed
	// On Alpine systems, returns installed packages
	// On non-Alpine systems, returns nil — both are acceptable
	pkgs := parseApkInstalled()
	for _, pkg := range pkgs {
		if pkg[0] == "" {
			t.Error("APK package name should not be empty")
		}
	}
}

func TestParseRpmDB(t *testing.T) {
	// parseRpmDB reads /var/lib/rpm/rpmdb.sqlite
	// On RPM-based systems with SQLite DB, returns installed packages
	// On non-RPM systems or legacy BDB, returns nil — both are acceptable
	pkgs := parseRpmDB()
	for _, pkg := range pkgs {
		if pkg[0] == "" {
			t.Error("RPM package name should not be empty")
		}
	}
}

func TestBeUint32(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		off  int
		want uint32
	}{
		{"zero", []byte{0, 0, 0, 0}, 0, 0},
		{"one", []byte{0, 0, 0, 1}, 0, 1},
		{"0xdeadbeef", []byte{0xde, 0xad, 0xbe, 0xef}, 0, 0xdeadbeef},
		{"with offset", []byte{0xff, 0, 0, 0, 1}, 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := beUint32(tt.data, tt.off)
			if got != tt.want {
				t.Errorf("beUint32 = 0x%x, want 0x%x", got, tt.want)
			}
		})
	}
}

func TestCStringAt(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		off  int
		want string
	}{
		{"simple", []byte{'h', 'i', 0}, 0, "hi"},
		{"with offset", []byte{0, 'o', 'k', 0}, 1, "ok"},
		{"empty", []byte{0}, 0, ""},
		{"no null", []byte{'a', 'b', 'c'}, 0, "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cStringAt(tt.data, tt.off)
			if got != tt.want {
				t.Errorf("cStringAt = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRpmParseHeaderBlob(t *testing.T) {
	// Build a minimal RPM header blob with magic, 3 index entries (Name, Version, Release),
	// and a data store with null-terminated strings.
	// Header format: magic(4) + pad(4) + nindex(4) + hsize(4) + index entries + data store

	data := []byte("bash\x00" + "5.1\x00" + "1.el9\x00") // data store: 16 bytes
	nindex := 3
	hsize := len(data)

	var blob []byte
	// Magic
	blob = append(blob, 0x8e, 0xad, 0xe8, 0x01)
	// Reserved/padding
	blob = append(blob, 0, 0, 0, 0)
	// nindex (BE)
	blob = append(blob, 0, 0, 0, byte(nindex))
	// hsize (BE)
	blob = append(blob, 0, 0, 0, byte(hsize))
	// Index entry 0: tag=1000 (Name), type=6 (STRING), offset=0, count=1
	blob = appendBE32(blob, 1000)
	blob = appendBE32(blob, 6)
	blob = appendBE32(blob, 0)
	blob = appendBE32(blob, 1)
	// Index entry 1: tag=1001 (Version), type=6, offset=5, count=1
	blob = appendBE32(blob, 1001)
	blob = appendBE32(blob, 6)
	blob = appendBE32(blob, 5) // "bash\0" is 5 bytes
	blob = appendBE32(blob, 1)
	// Index entry 2: tag=1002 (Release), type=6, offset=9, count=1
	blob = appendBE32(blob, 1002)
	blob = appendBE32(blob, 6)
	blob = appendBE32(blob, 9) // "bash\05.1\0" is 9 bytes
	blob = appendBE32(blob, 1)
	// Data store
	blob = append(blob, data...)

	name, ver := rpmParseHeaderBlob(blob)
	if name != "bash" {
		t.Errorf("name = %q, want 'bash'", name)
	}
	if ver != "5.1-1.el9" {
		t.Errorf("version = %q, want '5.1-1.el9'", ver)
	}
}

func TestRpmParseHeaderBlobTooShort(t *testing.T) {
	name, ver := rpmParseHeaderBlob([]byte{1, 2, 3})
	if name != "" || ver != "" {
		t.Error("expected empty for too-short blob")
	}
}

func TestRpmParseHeaderBlobNoMagic(t *testing.T) {
	blob := make([]byte, 100)
	name, ver := rpmParseHeaderBlob(blob)
	if name != "" || ver != "" {
		t.Error("expected empty for blob without magic")
	}
}

func appendBE32(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func TestPkgListLinux(t *testing.T) {
	output := pkgListLinux("")
	if !strings.Contains(output, "Installed Packages") {
		t.Error("Output should contain header")
	}
	// Should either find a package manager or report none found
	hasPkgMgr := strings.Contains(output, "Package Manager:") ||
		strings.Contains(output, "Snap packages:") ||
		strings.Contains(output, "Flatpak") ||
		strings.Contains(output, "No supported package manager")
	if !hasPkgMgr {
		t.Error("Output should report on package managers")
	}
}

func TestPkgListLinuxWithFilter(t *testing.T) {
	output := pkgListLinux("nonexistent_pkg_xyz")
	if !strings.Contains(output, "Installed Packages") {
		t.Error("Output should contain header even with filter")
	}
}
