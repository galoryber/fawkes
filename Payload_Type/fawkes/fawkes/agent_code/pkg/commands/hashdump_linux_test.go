//go:build linux

package commands

import "testing"

func TestIdentifyHashType(t *testing.T) {
	tests := []struct {
		hash     string
		expected string
	}{
		{"$y$j9T$abc$longhash", "yescrypt"},
		{"$6$rounds=5000$salt$hash", "SHA-512"},
		{"$5$salt$hash", "SHA-256"},
		{"$2b$12$salt.hash", "bcrypt"},
		{"$2a$10$salt.hash", "bcrypt"},
		{"$2y$12$salt.hash", "bcrypt"},
		{"$1$salt$hash", "MD5"},
		{"abcdefghijklm", "DES"},
		{"$7$something", "unknown"},
		{"!$6$locked", "locked"},
		{"*", "locked"},
	}
	for _, tt := range tests {
		got := identifyHashType(tt.hash)
		if got != tt.expected {
			t.Errorf("identifyHashType(%q) = %q, want %q", tt.hash, got, tt.expected)
		}
	}
}

func TestParsePasswd(t *testing.T) {
	data := []byte("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
	m := parsePasswd(data)

	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}

	root, ok := m["root"]
	if !ok {
		t.Fatal("missing root entry")
	}
	if root.uid != "0" || root.gid != "0" || root.home != "/root" || root.shell != "/bin/bash" {
		t.Errorf("root entry = %+v", root)
	}

	nobody, ok := m["nobody"]
	if !ok {
		t.Fatal("missing nobody entry")
	}
	if nobody.uid != "65534" || nobody.shell != "/usr/sbin/nologin" {
		t.Errorf("nobody entry = %+v", nobody)
	}
}

func TestParsePasswd_Nil(t *testing.T) {
	m := parsePasswd(nil)
	if len(m) != 0 {
		t.Errorf("expected empty map for nil input, got %d entries", len(m))
	}
}

func TestParsePasswd_MalformedLines(t *testing.T) {
	data := []byte("short:x\nroot:x:0:0:root:/root:/bin/bash\n::\n")
	m := parsePasswd(data)
	if len(m) != 1 {
		t.Errorf("expected 1 valid entry, got %d", len(m))
	}
	if _, ok := m["root"]; !ok {
		t.Error("missing root entry")
	}
}
