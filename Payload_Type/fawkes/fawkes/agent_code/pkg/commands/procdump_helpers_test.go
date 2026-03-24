package commands

import (
	"strings"
	"testing"
)

func TestParseMapsLine_Standard(t *testing.T) {
	line := "7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0                          "
	r, err := parseMapsLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Start != 0x7f8a1c000000 {
		t.Errorf("Start = 0x%x, want 0x7f8a1c000000", r.Start)
	}
	if r.End != 0x7f8a1c021000 {
		t.Errorf("End = 0x%x, want 0x7f8a1c021000", r.End)
	}
	if r.Perms != "rw-p" {
		t.Errorf("Perms = %q, want %q", r.Perms, "rw-p")
	}
	if r.Offset != 0 {
		t.Errorf("Offset = %d, want 0", r.Offset)
	}
	if r.Dev != "00:00" {
		t.Errorf("Dev = %q, want %q", r.Dev, "00:00")
	}
	if r.Inode != 0 {
		t.Errorf("Inode = %d, want 0", r.Inode)
	}
	if r.Pathname != "" {
		t.Errorf("Pathname = %q, want empty", r.Pathname)
	}
}

func TestParseMapsLine_WithPathname(t *testing.T) {
	line := "00400000-004b8000 r--p 00000000 08:01 123456                    /usr/bin/program"
	r, err := parseMapsLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Start != 0x00400000 {
		t.Errorf("Start = 0x%x, want 0x00400000", r.Start)
	}
	if r.End != 0x004b8000 {
		t.Errorf("End = 0x%x, want 0x004b8000", r.End)
	}
	if r.Perms != "r--p" {
		t.Errorf("Perms = %q, want %q", r.Perms, "r--p")
	}
	if r.Offset != 0 {
		t.Errorf("Offset = %d, want 0", r.Offset)
	}
	if r.Inode != 123456 {
		t.Errorf("Inode = %d, want 123456", r.Inode)
	}
	if r.Pathname != "/usr/bin/program" {
		t.Errorf("Pathname = %q, want %q", r.Pathname, "/usr/bin/program")
	}
}

func TestParseMapsLine_HeapRegion(t *testing.T) {
	line := "55a8f2e4a000-55a8f2e6b000 rw-p 00000000 00:00 0                          [heap]"
	r, err := parseMapsLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Pathname != "[heap]" {
		t.Errorf("Pathname = %q, want %q", r.Pathname, "[heap]")
	}
	if !r.IsReadable() {
		t.Error("expected IsReadable() = true")
	}
	if !r.IsWritable() {
		t.Error("expected IsWritable() = true")
	}
	if !r.IsPrivate() {
		t.Error("expected IsPrivate() = true")
	}
}

func TestParseMapsLine_StackRegion(t *testing.T) {
	line := "7ffc12300000-7ffc12321000 rw-p 00000000 00:00 0                          [stack]"
	r, err := parseMapsLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Pathname != "[stack]" {
		t.Errorf("Pathname = %q, want %q", r.Pathname, "[stack]")
	}
}

func TestParseMapsLine_VdsoRegion(t *testing.T) {
	line := "7ffc12345000-7ffc12347000 r-xp 00000000 00:00 0                          [vdso]"
	r, err := parseMapsLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Pathname != "[vdso]" {
		t.Errorf("Pathname = %q, want %q", r.Pathname, "[vdso]")
	}
}

func TestParseMapsLine_SharedMapping(t *testing.T) {
	line := "7f0000000000-7f0000100000 r--s 00000000 08:01 999999                    /dev/shm/test"
	r, err := parseMapsLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Perms != "r--s" {
		t.Errorf("Perms = %q, want %q", r.Perms, "r--s")
	}
	if r.IsPrivate() {
		t.Error("expected IsPrivate() = false for shared mapping")
	}
}

func TestParseMapsLine_ExecutableRegion(t *testing.T) {
	line := "00400000-00500000 r-xp 00001000 103:07 3423324                   /usr/bin/test"
	r, err := parseMapsLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Offset != 0x1000 {
		t.Errorf("Offset = 0x%x, want 0x1000", r.Offset)
	}
}

func TestParseMapsLine_EmptyLine(t *testing.T) {
	_, err := parseMapsLine("")
	if err == nil {
		t.Error("expected error for empty line")
	}
}

func TestParseMapsLine_TooFewFields(t *testing.T) {
	_, err := parseMapsLine("00400000-00500000 r-xp")
	if err == nil {
		t.Error("expected error for too few fields")
	}
}

func TestParseMapsLine_InvalidAddress(t *testing.T) {
	_, err := parseMapsLine("ZZZZ-00500000 r-xp 00000000 00:00 0")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestParseMapsLine_InvalidEndAddress(t *testing.T) {
	_, err := parseMapsLine("00400000-ZZZZZZ r-xp 00000000 00:00 0")
	if err == nil {
		t.Error("expected error for invalid end address")
	}
}

func TestParseMapsLine_MissingDash(t *testing.T) {
	_, err := parseMapsLine("0040000000500000 r-xp 00000000 00:00 0")
	if err == nil {
		t.Error("expected error for missing dash in address")
	}
}

func TestParseMapsLine_InvalidOffset(t *testing.T) {
	_, err := parseMapsLine("00400000-00500000 r-xp NOTAHEX 00:00 0")
	if err == nil {
		t.Error("expected error for invalid offset")
	}
}

func TestParseMapsLine_InvalidInode(t *testing.T) {
	_, err := parseMapsLine("00400000-00500000 r-xp 00000000 00:00 NOTANUM")
	if err == nil {
		t.Error("expected error for invalid inode")
	}
}

func TestMemoryRegion_Size(t *testing.T) {
	r := memoryRegion{Start: 0x1000, End: 0x2000}
	if r.Size() != 0x1000 {
		t.Errorf("Size() = %d, want %d", r.Size(), 0x1000)
	}
}

func TestMemoryRegion_SizeZero(t *testing.T) {
	r := memoryRegion{Start: 0x1000, End: 0x1000}
	if r.Size() != 0 {
		t.Errorf("Size() = %d, want 0", r.Size())
	}
}

func TestMemoryRegion_IsReadable(t *testing.T) {
	tests := []struct {
		perms string
		want  bool
	}{
		{"r--p", true},
		{"rw-p", true},
		{"r-xp", true},
		{"-w-p", false},
		{"---p", false},
		{"", false},
	}
	for _, tt := range tests {
		r := memoryRegion{Perms: tt.perms}
		if got := r.IsReadable(); got != tt.want {
			t.Errorf("IsReadable(%q) = %v, want %v", tt.perms, got, tt.want)
		}
	}
}

func TestMemoryRegion_IsWritable(t *testing.T) {
	tests := []struct {
		perms string
		want  bool
	}{
		{"rw-p", true},
		{"r--p", false},
		{"-w-p", true},
		{"", false},
		{"r", false},
	}
	for _, tt := range tests {
		r := memoryRegion{Perms: tt.perms}
		if got := r.IsWritable(); got != tt.want {
			t.Errorf("IsWritable(%q) = %v, want %v", tt.perms, got, tt.want)
		}
	}
}

func TestMemoryRegion_IsPrivate(t *testing.T) {
	tests := []struct {
		perms string
		want  bool
	}{
		{"rw-p", true},
		{"r--p", true},
		{"r--s", false},
		{"rw-s", false},
		{"", false},
		{"rw-", false},
	}
	for _, tt := range tests {
		r := memoryRegion{Perms: tt.perms}
		if got := r.IsPrivate(); got != tt.want {
			t.Errorf("IsPrivate(%q) = %v, want %v", tt.perms, got, tt.want)
		}
	}
}

func TestMemoryRegion_IsAnonymous(t *testing.T) {
	tests := []struct {
		pathname string
		want     bool
	}{
		{"", true},
		{"[heap]", false},
		{"/usr/lib/libc.so", false},
	}
	for _, tt := range tests {
		r := memoryRegion{Pathname: tt.pathname}
		if got := r.IsAnonymous(); got != tt.want {
			t.Errorf("IsAnonymous(%q) = %v, want %v", tt.pathname, got, tt.want)
		}
	}
}

func TestParseMapsContent(t *testing.T) {
	content := `55a8f2e4a000-55a8f2e6b000 rw-p 00000000 00:00 0                          [heap]
7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0
7ffc12345000-7ffc12347000 r-xp 00000000 00:00 0                          [vdso]
7ffc12300000-7ffc12321000 rw-p 00000000 00:00 0                          [stack]`

	regions := parseMapsContent(content)
	if len(regions) != 4 {
		t.Fatalf("expected 4 regions, got %d", len(regions))
	}
	if regions[0].Pathname != "[heap]" {
		t.Errorf("regions[0].Pathname = %q, want %q", regions[0].Pathname, "[heap]")
	}
	if regions[1].Pathname != "" {
		t.Errorf("regions[1].Pathname = %q, want empty", regions[1].Pathname)
	}
	if regions[2].Pathname != "[vdso]" {
		t.Errorf("regions[2].Pathname = %q, want %q", regions[2].Pathname, "[vdso]")
	}
	if regions[3].Pathname != "[stack]" {
		t.Errorf("regions[3].Pathname = %q, want %q", regions[3].Pathname, "[stack]")
	}
}

func TestParseMapsContent_EmptyContent(t *testing.T) {
	regions := parseMapsContent("")
	if len(regions) != 0 {
		t.Errorf("expected 0 regions for empty content, got %d", len(regions))
	}
}

func TestParseMapsContent_MalformedLines(t *testing.T) {
	content := `55a8f2e4a000-55a8f2e6b000 rw-p 00000000 00:00 0                          [heap]
this is not a valid line
7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0`

	regions := parseMapsContent(content)
	if len(regions) != 2 {
		t.Fatalf("expected 2 valid regions (skip malformed), got %d", len(regions))
	}
}

func TestFilterDumpableRegions(t *testing.T) {
	regions := []memoryRegion{
		{Start: 0x1000, End: 0x2000, Perms: "rw-p", Pathname: "[heap]"},             // dumpable
		{Start: 0x2000, End: 0x3000, Perms: "rw-p", Pathname: ""},                   // dumpable (anonymous)
		{Start: 0x3000, End: 0x4000, Perms: "r-xp", Pathname: "[vdso]"},             // skip (vdso)
		{Start: 0x4000, End: 0x5000, Perms: "r--p", Pathname: "[vvar]"},             // skip (vvar)
		{Start: 0x5000, End: 0x6000, Perms: "r-xp", Pathname: "[vsyscall]"},         // skip (vsyscall)
		{Start: 0x6000, End: 0x7000, Perms: "r--s", Pathname: "/dev/shm/foo"},       // skip (shared)
		{Start: 0x7000, End: 0x8000, Perms: "---p", Pathname: ""},                   // skip (not readable)
		{Start: 0x8000, End: 0x9000, Perms: "rw-p", Pathname: "[stack]"},            // dumpable
		{Start: 0x9000, End: 0xa000, Perms: "r--p", Pathname: "/usr/lib/libc.so.6"}, // dumpable (file-backed but readable+private)
	}

	result := filterDumpableRegions(regions)
	if len(result) != 4 {
		t.Fatalf("expected 4 dumpable regions, got %d", len(result))
	}
	if result[0].Pathname != "[heap]" {
		t.Errorf("result[0].Pathname = %q, want %q", result[0].Pathname, "[heap]")
	}
	if result[1].Pathname != "" {
		t.Errorf("result[1].Pathname = %q, want empty", result[1].Pathname)
	}
	if result[2].Pathname != "[stack]" {
		t.Errorf("result[2].Pathname = %q, want %q", result[2].Pathname, "[stack]")
	}
	if result[3].Pathname != "/usr/lib/libc.so.6" {
		t.Errorf("result[3].Pathname = %q, want %q", result[3].Pathname, "/usr/lib/libc.so.6")
	}
}

func TestFilterDumpableRegions_AllFiltered(t *testing.T) {
	regions := []memoryRegion{
		{Start: 0x1000, End: 0x2000, Perms: "r-xp", Pathname: "[vdso]"},
		{Start: 0x2000, End: 0x3000, Perms: "---p", Pathname: ""},
		{Start: 0x3000, End: 0x4000, Perms: "r--s", Pathname: ""},
	}
	result := filterDumpableRegions(regions)
	if len(result) != 0 {
		t.Errorf("expected 0 dumpable regions, got %d", len(result))
	}
}

func TestFilterDumpableRegions_Empty(t *testing.T) {
	result := filterDumpableRegions(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 dumpable regions for nil input, got %d", len(result))
	}
}

func TestTotalRegionSize(t *testing.T) {
	regions := []memoryRegion{
		{Start: 0x1000, End: 0x2000},
		{Start: 0x3000, End: 0x5000},
		{Start: 0x6000, End: 0x6100},
	}
	total := totalRegionSize(regions)
	expected := uint64(0x1000 + 0x2000 + 0x100)
	if total != expected {
		t.Errorf("totalRegionSize = %d, want %d", total, expected)
	}
}

func TestTotalRegionSize_Empty(t *testing.T) {
	total := totalRegionSize(nil)
	if total != 0 {
		t.Errorf("totalRegionSize(nil) = %d, want 0", total)
	}
}

func TestSanitizeFileName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sshd", "sshd"},
		{"my process", "my_process"},
		{"path/to/file", "path_to_file"},
		{"test:file", "test_file"},
		{"file*name?", "file_name_"},
		{"", ""},
	}
	for _, tt := range tests {
		got := sanitizeFileName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeFileName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeFileName_TruncatesLong(t *testing.T) {
	long := strings.Repeat("a", 50)
	got := sanitizeFileName(long)
	if len(got) > 32 {
		t.Errorf("sanitizeFileName should truncate to 32 chars, got %d", len(got))
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello world", 8, "hello..."},
		{"short", 5, "short"},
		{"ab", 10, "ab"},
	}
	for _, tt := range tests {
		got := truncateString(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestParseMapsLine_RealWorldExamples(t *testing.T) {
	// Real /proc/pid/maps lines from various Linux systems
	tests := []struct {
		name string
		line string
		want memoryRegion
	}{
		{
			name: "binary_text",
			line: "63e50b15c000-63e50b162000 r-xp 00002000 103:07 3423324                   /usr/bin/head",
			want: memoryRegion{Start: 0x63e50b15c000, End: 0x63e50b162000, Perms: "r-xp", Offset: 0x2000, Dev: "103:07", Inode: 3423324, Pathname: "/usr/bin/head"},
		},
		{
			name: "libc_data",
			line: "7f0a8c1f0000-7f0a8c1f3000 rw-p 001b5000 103:07 3417539                   /usr/lib/x86_64-linux-gnu/libc.so.6",
			want: memoryRegion{Start: 0x7f0a8c1f0000, End: 0x7f0a8c1f3000, Perms: "rw-p", Offset: 0x1b5000, Dev: "103:07", Inode: 3417539, Pathname: "/usr/lib/x86_64-linux-gnu/libc.so.6"},
		},
		{
			name: "anon_mapping",
			line: "7f0a8c200000-7f0a8c220000 rw-p 00000000 00:00 0",
			want: memoryRegion{Start: 0x7f0a8c200000, End: 0x7f0a8c220000, Perms: "rw-p", Offset: 0, Dev: "00:00", Inode: 0, Pathname: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMapsLine(tt.line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Start != tt.want.Start {
				t.Errorf("Start = 0x%x, want 0x%x", got.Start, tt.want.Start)
			}
			if got.End != tt.want.End {
				t.Errorf("End = 0x%x, want 0x%x", got.End, tt.want.End)
			}
			if got.Perms != tt.want.Perms {
				t.Errorf("Perms = %q, want %q", got.Perms, tt.want.Perms)
			}
			if got.Offset != tt.want.Offset {
				t.Errorf("Offset = 0x%x, want 0x%x", got.Offset, tt.want.Offset)
			}
			if got.Inode != tt.want.Inode {
				t.Errorf("Inode = %d, want %d", got.Inode, tt.want.Inode)
			}
			if got.Pathname != tt.want.Pathname {
				t.Errorf("Pathname = %q, want %q", got.Pathname, tt.want.Pathname)
			}
		})
	}
}

func TestCredentialProcessesList(t *testing.T) {
	// Ensure the list is populated and has expected entries
	if len(credentialProcesses) == 0 {
		t.Error("credentialProcesses should not be empty")
	}
	// Check a few known entries exist
	found := make(map[string]bool)
	for _, p := range credentialProcesses {
		found[p] = true
	}
	for _, expected := range []string{"sshd", "ssh-agent", "sudo", "gpg-agent"} {
		if !found[expected] {
			t.Errorf("credentialProcesses should contain %q", expected)
		}
	}
}
