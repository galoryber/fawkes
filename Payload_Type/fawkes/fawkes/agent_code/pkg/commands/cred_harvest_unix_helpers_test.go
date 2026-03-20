//go:build !windows

package commands

import "testing"

// --- parseShadowLines tests ---

func TestParseShadowLines_ValidEntries(t *testing.T) {
	lines := []string{
		"root:$6$salt$hash:19000:0:99999:7:::",
		"user1:$y$j9T$salt$hash:19500:0:99999:7:::",
		"daemon:*:19000:0:99999:7:::",
		"nobody:!:19000:0:99999:7:::",
	}
	entries := parseShadowLines(lines, "")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (root, user1), got %d", len(entries))
	}
	if entries[0].User != "root" {
		t.Errorf("entries[0].User = %q, want root", entries[0].User)
	}
	if entries[1].User != "user1" {
		t.Errorf("entries[1].User = %q, want user1", entries[1].User)
	}
}

func TestParseShadowLines_LockedAccounts(t *testing.T) {
	lines := []string{
		"locked1:!$6$hash:19000:0:99999:7:::",     // locked (! prefix)
		"locked2:!!:19000:0:99999:7:::",            // double-locked
		"disabled:*:19000:0:99999:7:::",            // disabled
		"empty::19000:0:99999:7:::",                // empty hash
		"active:$6$salt$realhash:19000:0:99999:7:::", // active
	}
	entries := parseShadowLines(lines, "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 active entry, got %d", len(entries))
	}
	if entries[0].User != "active" {
		t.Errorf("expected 'active', got %q", entries[0].User)
	}
}

func TestParseShadowLines_UserFilter(t *testing.T) {
	lines := []string{
		"root:$6$hash1:19000:0:99999:7:::",
		"admin:$6$hash2:19000:0:99999:7:::",
		"svc_admin:$6$hash3:19000:0:99999:7:::",
		"user:$6$hash4:19000:0:99999:7:::",
	}

	// Filter for "admin" — should match admin and svc_admin
	entries := parseShadowLines(lines, "admin")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries matching 'admin', got %d", len(entries))
	}
	if entries[0].User != "admin" || entries[1].User != "svc_admin" {
		t.Errorf("got users %q and %q", entries[0].User, entries[1].User)
	}
}

func TestParseShadowLines_UserFilterCaseInsensitive(t *testing.T) {
	lines := []string{
		"Admin:$6$hash:19000:0:99999:7:::",
		"ADMIN:$6$hash:19000:0:99999:7:::",
		"other:$6$hash:19000:0:99999:7:::",
	}
	entries := parseShadowLines(lines, "admin")
	if len(entries) != 2 {
		t.Fatalf("expected 2 case-insensitive matches, got %d", len(entries))
	}
}

func TestParseShadowLines_EmptyInput(t *testing.T) {
	entries := parseShadowLines(nil, "")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nil input, got %d", len(entries))
	}

	entries = parseShadowLines([]string{}, "")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty slice, got %d", len(entries))
	}
}

func TestParseShadowLines_SkipsEmptyAndMalformed(t *testing.T) {
	lines := []string{
		"",
		"malformed",
		"valid:$6$hash:rest",
	}
	entries := parseShadowLines(lines, "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(entries))
	}
}

func TestParseShadowLines_HashTypes(t *testing.T) {
	lines := []string{
		"md5:$1$salt$hash:19000:0:99999:7:::",
		"sha256:$5$salt$hash:19000:0:99999:7:::",
		"sha512:$6$salt$hash:19000:0:99999:7:::",
		"yescrypt:$y$j9T$salt$hash:19000:0:99999:7:::",
		"blowfish:$2b$12$salt$hash:19000:0:99999:7:::",
	}
	entries := parseShadowLines(lines, "")
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries (all hash types), got %d", len(entries))
	}
	for i, e := range entries {
		if e.Hash == "" {
			t.Errorf("entries[%d].Hash is empty", i)
		}
	}
}

func TestParseShadowLines_PreservesFullHash(t *testing.T) {
	// Verify that hashes with colons in the remainder are preserved correctly
	lines := []string{
		"user:$6$rounds=5000$saltsalt$longhashabcdef123456:19000:0:99999:7:::",
	}
	entries := parseShadowLines(lines, "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Hash != "$6$rounds=5000$saltsalt$longhashabcdef123456" {
		t.Errorf("hash = %q", entries[0].Hash)
	}
}

// --- parsePasswdLines tests ---

func TestParsePasswdLines_ValidEntries(t *testing.T) {
	lines := []string{
		"root:x:0:0:root:/root:/bin/bash",
		"user1:x:1000:1000:User One:/home/user1:/bin/zsh",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
	}
	entries := parsePasswdLines(lines, "")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (root, user1), got %d", len(entries))
	}
	if entries[0].User != "root" || entries[0].Shell != "/bin/bash" {
		t.Errorf("entries[0] = %+v", entries[0])
	}
	if entries[1].User != "user1" || entries[1].UID != "1000" || entries[1].GID != "1000" {
		t.Errorf("entries[1] = %+v", entries[1])
	}
}

func TestParsePasswdLines_NologinVariants(t *testing.T) {
	lines := []string{
		"svc1:x:100:100::/home/svc1:/usr/sbin/nologin",
		"svc2:x:101:101::/home/svc2:/bin/false",
		"svc3:x:102:102::/home/svc3:/usr/bin/nologin",
		"svc4:x:103:103::/home/svc4:/sbin/nologin",
		"active:x:1000:1000::/home/active:/bin/sh",
	}
	entries := parsePasswdLines(lines, "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (active), got %d", len(entries))
	}
	if entries[0].User != "active" {
		t.Errorf("expected 'active', got %q", entries[0].User)
	}
}

func TestParsePasswdLines_LegacyPasswordHash(t *testing.T) {
	lines := []string{
		"legacy:$1$salt$hash:0:0:Legacy:/root:/bin/bash", // hash in passwd field
		"normal:x:1000:1000:Normal:/home/normal:/bin/bash",
	}
	entries := parsePasswdLines(lines, "")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].PasswdHash != "$1$salt$hash" {
		t.Errorf("expected legacy hash, got %q", entries[0].PasswdHash)
	}
	if entries[1].PasswdHash != "" {
		t.Errorf("normal user should have empty PasswdHash, got %q", entries[1].PasswdHash)
	}
}

func TestParsePasswdLines_UserFilter(t *testing.T) {
	lines := []string{
		"root:x:0:0:root:/root:/bin/bash",
		"user1:x:1000:1000::/home/user1:/bin/bash",
		"user2:x:1001:1001::/home/user2:/bin/bash",
	}
	entries := parsePasswdLines(lines, "user")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries matching 'user', got %d", len(entries))
	}
}

func TestParsePasswdLines_EmptyInput(t *testing.T) {
	entries := parsePasswdLines(nil, "")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nil input, got %d", len(entries))
	}
}

func TestParsePasswdLines_MalformedLines(t *testing.T) {
	lines := []string{
		"too:few:fields",
		"",
		"valid:x:1000:1000:User:/home/user:/bin/bash",
	}
	entries := parsePasswdLines(lines, "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(entries))
	}
}

func TestParsePasswdLines_FieldExtraction(t *testing.T) {
	lines := []string{
		"testuser:x:1234:5678:Test User:/home/testuser:/bin/fish",
	}
	entries := parsePasswdLines(lines, "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.User != "testuser" || e.UID != "1234" || e.GID != "5678" ||
		e.Home != "/home/testuser" || e.Shell != "/bin/fish" {
		t.Errorf("field extraction failed: %+v", e)
	}
}

func TestParsePasswdLines_StarAndEmptyPasswd(t *testing.T) {
	lines := []string{
		"user1:*:1000:1000::/home/user1:/bin/bash",
		"user2::1001:1001::/home/user2:/bin/bash",
	}
	entries := parsePasswdLines(lines, "")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// * and empty should NOT be treated as legacy hashes
	if entries[0].PasswdHash != "" {
		t.Errorf("* should not be a passwd hash, got %q", entries[0].PasswdHash)
	}
	if entries[1].PasswdHash != "" {
		t.Errorf("empty should not be a passwd hash, got %q", entries[1].PasswdHash)
	}
}

// --- parseGshadowLines tests ---

func TestParseGshadowLines_ValidEntries(t *testing.T) {
	lines := []string{
		"wheel:$6$salt$hash:root:user1",
		"admin:secretpass:root:",
		"nopass:!:root:",
		"empty::root:",
		"star:*:root:",
	}
	entries := parseGshadowLines(lines)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (wheel, admin), got %d", len(entries))
	}
	if entries[0].Line != "wheel:$6$salt$hash:root:user1" {
		t.Errorf("entries[0].Line = %q", entries[0].Line)
	}
}

func TestParseGshadowLines_EmptyInput(t *testing.T) {
	entries := parseGshadowLines(nil)
	if len(entries) != 0 {
		t.Errorf("expected 0, got %d", len(entries))
	}
	entries = parseGshadowLines([]string{})
	if len(entries) != 0 {
		t.Errorf("expected 0, got %d", len(entries))
	}
}

func TestParseGshadowLines_AllInactive(t *testing.T) {
	lines := []string{
		"group1:!:root:",
		"group2::root:",
		"group3:*:root:",
	}
	entries := parseGshadowLines(lines)
	if len(entries) != 0 {
		t.Errorf("expected 0 (all inactive), got %d", len(entries))
	}
}

func TestParseGshadowLines_MalformedLines(t *testing.T) {
	lines := []string{
		"nodelimiter",
		"",
		"valid:password:admins:user1,user2",
	}
	entries := parseGshadowLines(lines)
	if len(entries) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(entries))
	}
}
