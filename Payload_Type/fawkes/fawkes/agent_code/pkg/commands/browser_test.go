//go:build windows

package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestBrowserCommand_Name(t *testing.T) {
	cmd := &BrowserCommand{}
	if cmd.Name() != "browser" {
		t.Errorf("expected 'browser', got %q", cmd.Name())
	}
}

func TestBrowserCommand_Description(t *testing.T) {
	cmd := &BrowserCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestBrowserCommand_EmptyParams(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	// Should run with default args (passwords, all) — will report no browsers found
	if result.Status != "success" {
		t.Errorf("expected success status with empty params, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserCommand_InvalidJSON(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	// Should fall back to defaults
	if result.Status != "success" {
		t.Errorf("expected success status with invalid JSON, got %q", result.Status)
	}
}

func TestBrowserCommand_UnknownAction(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
}

func TestBrowserCommand_ChromeOnly(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"browser":"chrome"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserCommand_EdgeOnly(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"browser":"edge"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserPaths_All(t *testing.T) {
	paths := browserPaths("all")
	if paths == nil {
		t.Skip("LOCALAPPDATA not set")
	}
	if _, ok := paths["Chrome"]; !ok {
		t.Error("expected Chrome path")
	}
	if _, ok := paths["Edge"]; !ok {
		t.Error("expected Edge path")
	}
}

func TestBrowserPaths_Chrome(t *testing.T) {
	paths := browserPaths("chrome")
	if paths == nil {
		t.Skip("LOCALAPPDATA not set")
	}
	if len(paths) != 1 {
		t.Errorf("expected 1 path for chrome, got %d", len(paths))
	}
	if _, ok := paths["Chrome"]; !ok {
		t.Error("expected Chrome path only")
	}
}

func TestBrowserPaths_Edge(t *testing.T) {
	paths := browserPaths("edge")
	if paths == nil {
		t.Skip("LOCALAPPDATA not set")
	}
	if len(paths) != 1 {
		t.Errorf("expected 1 path for edge, got %d", len(paths))
	}
	if _, ok := paths["Edge"]; !ok {
		t.Error("expected Edge path only")
	}
}

func TestDecryptPassword_AES_GCM(t *testing.T) {
	// Create a known key and encrypt some test data
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := "testpassword123"
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Build the encrypted blob: "v10" + nonce + ciphertext
	encrypted := append([]byte("v10"), nonce...)
	encrypted = append(encrypted, ciphertext...)

	result, err := decryptPassword(encrypted, key)
	if err != nil {
		t.Fatalf("decryptPassword failed: %v", err)
	}
	if result != plaintext {
		t.Errorf("expected %q, got %q", plaintext, result)
	}
}

func TestDecryptPassword_V11Prefix(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := "v11password"
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	encrypted := append([]byte("v11"), nonce...)
	encrypted = append(encrypted, ciphertext...)

	result, err := decryptPassword(encrypted, key)
	if err != nil {
		t.Fatalf("decryptPassword failed: %v", err)
	}
	if result != plaintext {
		t.Errorf("expected %q, got %q", plaintext, result)
	}
}

func TestDecryptPassword_TooShort(t *testing.T) {
	_, err := decryptPassword([]byte("v10abc"), make([]byte, 32))
	if err == nil {
		t.Error("expected error for too-short encrypted data")
	}
}

func TestDecryptPassword_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, nonce, []byte("secret"), nil)

	encrypted := append([]byte("v10"), nonce...)
	encrypted = append(encrypted, ciphertext...)

	_, err := decryptPassword(encrypted, wrongKey)
	if err == nil {
		t.Error("expected error with wrong key")
	}
}

func TestBrowserCommand_CookiesAction(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"cookies"}`})
	// Should succeed even with no browsers installed
	if result.Status != "success" {
		t.Errorf("expected success for cookies action, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserCommand_CookiesChromeOnly(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"cookies","browser":"chrome"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserArgs_Defaults(t *testing.T) {
	var args browserArgs
	json.Unmarshal([]byte(`{}`), &args)
	if args.Action != "" {
		t.Errorf("expected empty action, got %q", args.Action)
	}
	// The Execute function fills in defaults
}

func TestBrowserArgs_Full(t *testing.T) {
	var args browserArgs
	err := json.Unmarshal([]byte(`{"action":"passwords","browser":"chrome"}`), &args)
	if err != nil {
		t.Fatal(err)
	}
	if args.Action != "passwords" {
		t.Errorf("expected 'passwords', got %q", args.Action)
	}
	if args.Browser != "chrome" {
		t.Errorf("expected 'chrome', got %q", args.Browser)
	}
}

func TestChromeTimeToString(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected string
	}{
		{"zero", 0, "never"},
		{"negative", -1, "never"},
		// Chrome epoch: 2024-01-15 12:00:00 UTC = 13351536000000000
		{"chrome-epoch", 13351536000000000, "2024-01-15 12:00:00"},
		// Chrome epoch: 2020-01-01 00:00:00 UTC
		{"chrome-2020", 13228272000000000, "2020-01-01 00:00:00"},
		// Unix epoch seconds: 2024-01-15 12:00:00 UTC = 1705320000
		{"unix-epoch", 1705320000, "2024-01-15 12:00:00"},
		// Unix epoch seconds: 2020-01-01 00:00:00 UTC = 1577836800
		{"unix-2020", 1577836800, "2020-01-01 00:00:00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := chromeTimeToString(tt.input)
			if got != tt.expected {
				t.Errorf("chromeTimeToString(%d) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractBookmarks(t *testing.T) {
	root := bookmarkNode{
		Type: "folder",
		Name: "Bookmark Bar",
		Children: []bookmarkNode{
			{Type: "url", Name: "Google", URL: "https://google.com"},
			{Type: "folder", Name: "Work", Children: []bookmarkNode{
				{Type: "url", Name: "GitHub", URL: "https://github.com"},
				{Type: "url", Name: "Jira", URL: "https://jira.example.com"},
			}},
			{Type: "url", Name: "No URL", URL: ""},
		},
	}

	var bookmarks []browserBookmarkEntry
	extractBookmarks(&root, "Chrome", "bookmark_bar", &bookmarks)

	if len(bookmarks) != 3 {
		t.Fatalf("expected 3 bookmarks, got %d", len(bookmarks))
	}

	if bookmarks[0].Name != "Google" || bookmarks[0].URL != "https://google.com" {
		t.Errorf("first bookmark: got %+v", bookmarks[0])
	}
	if bookmarks[1].Folder != "bookmark_bar/Work" {
		t.Errorf("expected folder 'bookmark_bar/Work', got %q", bookmarks[1].Folder)
	}
	if bookmarks[2].Name != "Jira" {
		t.Errorf("expected 'Jira', got %q", bookmarks[2].Name)
	}
}

func TestExtractBookmarks_Empty(t *testing.T) {
	root := bookmarkNode{Type: "folder", Name: "empty"}
	var bookmarks []browserBookmarkEntry
	extractBookmarks(&root, "Chrome", "other", &bookmarks)
	if len(bookmarks) != 0 {
		t.Errorf("expected 0 bookmarks, got %d", len(bookmarks))
	}
}

func TestBrowserCommand_HistoryAction(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"history"}`})
	if result.Status != "success" {
		t.Errorf("expected success for history action, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserCommand_AutofillAction(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"autofill"}`})
	if result.Status != "success" {
		t.Errorf("expected success for autofill action, got %q: %s", result.Status, result.Output)
	}
}

func TestBrowserCommand_BookmarksAction(t *testing.T) {
	cmd := &BrowserCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"bookmarks"}`})
	if result.Status != "success" {
		t.Errorf("expected success for bookmarks action, got %q: %s", result.Status, result.Output)
	}
}
