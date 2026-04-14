package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDecodePuTTYSessionName_Plain(t *testing.T) {
	if got := decodePuTTYSessionName("my-server"); got != "my-server" {
		t.Errorf("plain name: got %q", got)
	}
}

func TestDecodePuTTYSessionName_Encoded(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Production%20Server", "Production Server"},
		{"host%3A22", "host:22"},
		{"10%2E0%2E0%2E1", "10.0.0.1"},
		{"no-encoding", "no-encoding"},
		{"bad%ZZ", "bad%ZZ"},     // invalid hex preserved
		{"trailing%2", "trailing%2"}, // incomplete sequence preserved
		{"", ""},                     // empty string
		{"%41%42%43", "ABC"},         // all encoded
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := decodePuTTYSessionName(tt.input); got != tt.want {
				t.Errorf("decodePuTTYSessionName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestUnhex(t *testing.T) {
	tests := []struct {
		input byte
		want  int
	}{
		{'0', 0}, {'5', 5}, {'9', 9},
		{'a', 10}, {'c', 12}, {'f', 15},
		{'A', 10}, {'C', 12}, {'F', 15},
		{'g', -1}, {'G', -1}, {'!', -1}, {' ', -1},
	}
	for _, tt := range tests {
		if got := unhex(tt.input); got != tt.want {
			t.Errorf("unhex(%c) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParsePPKHeader_V2(t *testing.T) {
	tmp := t.TempDir()
	ppkPath := filepath.Join(tmp, "test.ppk")
	os.WriteFile(ppkPath, []byte("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: aes256-cbc\nComment: rsa-key-20240101\nPublic-Lines: 6\nAAAAB3NzaC1yc2E...\n"), 0600)

	info := parsePPKHeader(ppkPath)
	if info.path != ppkPath {
		t.Errorf("path = %q", info.path)
	}
	if info.version != 2 {
		t.Errorf("version = %d, want 2", info.version)
	}
	if info.keyType != "ssh-rsa" {
		t.Errorf("keyType = %q, want ssh-rsa", info.keyType)
	}
	if info.encryption != "aes256-cbc" {
		t.Errorf("encryption = %q, want aes256-cbc", info.encryption)
	}
	if info.comment != "rsa-key-20240101" {
		t.Errorf("comment = %q", info.comment)
	}
}

func TestParsePPKHeader_V3(t *testing.T) {
	tmp := t.TempDir()
	ppkPath := filepath.Join(tmp, "test.ppk")
	os.WriteFile(ppkPath, []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: ed25519-key\nPublic-Lines: 2\n"), 0600)

	info := parsePPKHeader(ppkPath)
	if info.version != 3 {
		t.Errorf("version = %d, want 3", info.version)
	}
	if info.keyType != "ssh-ed25519" {
		t.Errorf("keyType = %q", info.keyType)
	}
	if info.encryption != "none" {
		t.Errorf("encryption = %q", info.encryption)
	}
}

func TestParsePPKHeader_V2ECDSA(t *testing.T) {
	tmp := t.TempDir()
	ppkPath := filepath.Join(tmp, "ecdsa.ppk")
	os.WriteFile(ppkPath, []byte("PuTTY-User-Key-File-2: ecdsa-sha2-nistp256\nEncryption: aes256-cbc\nComment: ecdsa-key\n"), 0600)

	info := parsePPKHeader(ppkPath)
	if info.keyType != "ecdsa-sha2-nistp256" {
		t.Errorf("keyType = %q", info.keyType)
	}
}

func TestParsePPKHeader_NotPPK(t *testing.T) {
	tmp := t.TempDir()
	ppkPath := filepath.Join(tmp, "notappk.ppk")
	os.WriteFile(ppkPath, []byte("This is not a PPK file at all.\nJust random text.\n"), 0600)

	info := parsePPKHeader(ppkPath)
	if info.path != "" {
		t.Error("non-PPK file should return empty ppkInfo")
	}
}

func TestParsePPKHeader_NonExistent(t *testing.T) {
	info := parsePPKHeader("/nonexistent/test.ppk")
	if info.path != "" {
		t.Error("non-existent file should return empty ppkInfo")
	}
}

func TestParsePPKHeader_NoEncryptionField(t *testing.T) {
	tmp := t.TempDir()
	ppkPath := filepath.Join(tmp, "test.ppk")
	os.WriteFile(ppkPath, []byte("PuTTY-User-Key-File-2: ecdsa-sha2-nistp256\nComment: my key\nPublic-Lines: 3\n"), 0600)

	info := parsePPKHeader(ppkPath)
	if info.encryption != "none" {
		t.Errorf("missing encryption field should default to 'none', got %q", info.encryption)
	}
}

func TestListSSHKeysInDir(t *testing.T) {
	tmp := t.TempDir()
	for _, name := range []string{"id_rsa", "id_rsa.pub", "authorized_keys", "config", "known_hosts", "random.txt", "notes.md"} {
		os.WriteFile(filepath.Join(tmp, name), []byte("test"), 0600)
	}
	os.WriteFile(filepath.Join(tmp, "mykey.ppk"), []byte("test"), 0600)

	keys := listSSHKeysInDir(tmp)
	if len(keys) != 6 {
		t.Errorf("expected 6 SSH-related files, got %d: %v", len(keys), keys)
	}
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}
	if keySet["random.txt"] {
		t.Error("random.txt should not be in SSH key list")
	}
	if keySet["notes.md"] {
		t.Error("notes.md should not be in SSH key list")
	}
}

func TestListSSHKeysInDir_Empty(t *testing.T) {
	tmp := t.TempDir()
	keys := listSSHKeysInDir(tmp)
	if len(keys) != 0 {
		t.Errorf("expected 0 keys in empty dir, got %d", len(keys))
	}
}

func TestListSSHKeysInDir_NonExistent(t *testing.T) {
	keys := listSSHKeysInDir("/nonexistent/dir")
	if keys != nil {
		t.Error("expected nil for non-existent directory")
	}
}

func TestFindPPKFilesInDirs(t *testing.T) {
	tmp := t.TempDir()
	dir1 := filepath.Join(tmp, "dir1")
	dir2 := filepath.Join(tmp, "dir2")
	os.MkdirAll(dir1, 0755)
	os.MkdirAll(dir2, 0755)

	// Write valid PPK files
	os.WriteFile(filepath.Join(dir1, "key1.ppk"), []byte("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: key1\n"), 0600)
	os.WriteFile(filepath.Join(dir2, "key2.ppk"), []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: key2\n"), 0600)
	// Write non-PPK file with .ppk extension
	os.WriteFile(filepath.Join(dir1, "fake.ppk"), []byte("not a ppk file\n"), 0600)
	// Write non-PPK file
	os.WriteFile(filepath.Join(dir1, "readme.txt"), []byte("hello\n"), 0600)

	results := findPPKFilesInDirs([]string{dir1, dir2, "/nonexistent"})
	if len(results) != 2 {
		t.Fatalf("expected 2 valid PPK files, got %d", len(results))
	}

	// Verify metadata
	for _, r := range results {
		if r.keyType == "" {
			t.Errorf("keyType should not be empty for %s", r.path)
		}
	}
}

func TestFindPPKFilesInDirs_Dedup(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "key.ppk"), []byte("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\n"), 0600)

	// Same directory listed twice should not produce duplicates
	results := findPPKFilesInDirs([]string{tmp, tmp})
	if len(results) != 1 {
		t.Errorf("expected 1 result (deduped), got %d", len(results))
	}
}

func TestFindPPKFilesInDirs_EmptyDirs(t *testing.T) {
	results := findPPKFilesInDirs([]string{})
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty dirs, got %d", len(results))
	}
}
