package commands

import (
	"runtime"
	"strings"
	"testing"
)

// --- ideVSCodeConfigDirs tests ---

func TestIdeVSCodeConfigDirs_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	dirs := ideVSCodeConfigDirs("/home/testuser")
	if len(dirs) < 1 {
		t.Fatal("expected at least one config dir on Linux")
	}
	for _, d := range dirs {
		if !strings.Contains(d, ".config/Code") {
			t.Errorf("Linux config dir %q should contain .config/Code", d)
		}
	}
}

func TestIdeVSCodeConfigDirs_ContainsHome(t *testing.T) {
	home := "/custom/home/user"
	dirs := ideVSCodeConfigDirs(home)
	if len(dirs) == 0 {
		t.Fatal("expected at least one config dir")
	}
	for _, d := range dirs {
		if !strings.HasPrefix(d, home) && !strings.Contains(d, "AppData") {
			// Windows path may use APPDATA env var, not home prefix
			if runtime.GOOS != "windows" {
				t.Errorf("config dir %q should be based on home %s", d, home)
			}
		}
	}
}

func TestIdeVSCodeConfigDirs_IncludesInsiders(t *testing.T) {
	dirs := ideVSCodeConfigDirs("/home/user")
	var hasInsiders bool
	for _, d := range dirs {
		if strings.Contains(d, "Insiders") {
			hasInsiders = true
			break
		}
	}
	if !hasInsiders {
		t.Error("expected at least one VS Code Insiders config dir")
	}
}

// --- ideCategorizExtensions tests ---

func TestIdeCategorizExtensions_SecurityExtensions(t *testing.T) {
	exts := []string{
		"snyk.snyk-security",
		"ms-azuretools.vscode-docker",
		"hashicorp.terraform",
		"trivy-vuln-scanner",
	}
	security, remote, other := ideCategorizExtensions(exts)
	if len(security) == 0 {
		t.Error("expected at least one security extension to be categorized")
	}
	for _, ext := range security {
		lower := strings.ToLower(ext)
		if !ideMatchesAny(lower, "snyk", "docker", "terraform", "trivy") {
			t.Errorf("unexpected security extension: %q", ext)
		}
	}
	_ = remote
	_ = other
}

func TestIdeCategorizExtensions_RemoteExtensions(t *testing.T) {
	exts := []string{
		"ms-vscode-remote.remote-ssh",
		"ms-vscode-remote.remote-wsl",
		"ms-vscode-remote.remote-containers",
		"ms-vscode.go-extension",
	}
	_, remote, _ := ideCategorizExtensions(exts)
	if len(remote) < 3 {
		t.Errorf("remote extension count = %d, want at least 3", len(remote))
	}
}

func TestIdeCategorizExtensions_OtherExtensions(t *testing.T) {
	exts := []string{"ms-vscode.cpptools", "golang.go", "dbaeumer.vscode-eslint"}
	_, _, other := ideCategorizExtensions(exts)
	if len(other) != 3 {
		t.Errorf("other count = %d, want 3", len(other))
	}
}

func TestIdeCategorizExtensions_Empty(t *testing.T) {
	security, remote, other := ideCategorizExtensions(nil)
	if security != nil || remote != nil || other != nil {
		t.Error("empty input should return nil slices")
	}
}

// --- ideExtractInterestingSettings tests ---

func TestIdeExtractInterestingSettings_KnownKeys(t *testing.T) {
	settings := map[string]interface{}{
		"http.proxy":                  "http://proxy.corp.com:8080",
		"remote.SSH.configFile":       "/home/user/.ssh/config",
		"docker.host":                 "tcp://docker.host:2375",
		"unrelated.setting":           "value",
	}
	items := ideExtractInterestingSettings(settings)
	if len(items) < 3 {
		t.Errorf("items count = %d, want at least 3 interesting settings", len(items))
	}
	// Check that http.proxy is found
	found := false
	for _, item := range items {
		if strings.Contains(item, "http.proxy") {
			found = true
			break
		}
	}
	if !found {
		t.Error("http.proxy not found in interesting settings")
	}
}

func TestIdeExtractInterestingSettings_LongValueTruncated(t *testing.T) {
	settings := map[string]interface{}{
		"app.apikey": strings.Repeat("x", 200),
	}
	items := ideExtractInterestingSettings(settings)
	if len(items) == 0 {
		t.Fatal("expected at least one item")
	}
	// The value should be truncated to 100+... chars
	if len(items[0]) > 200 {
		t.Errorf("long value should be truncated, got length %d", len(items[0]))
	}
	if !strings.Contains(items[0], "...") {
		t.Error("truncated value should contain ...")
	}
}

func TestIdeExtractInterestingSettings_EmptySettings(t *testing.T) {
	items := ideExtractInterestingSettings(map[string]interface{}{})
	if items != nil {
		t.Errorf("empty settings should return nil, got %v", items)
	}
}

func TestIdeExtractInterestingSettings_NoInterestingKeys(t *testing.T) {
	settings := map[string]interface{}{
		"editor.fontSize":    14,
		"editor.tabSize":     4,
		"workbench.theme":    "Default Dark+",
	}
	items := ideExtractInterestingSettings(settings)
	if len(items) != 0 {
		t.Errorf("no interesting keys, expected 0 items, got %d: %v", len(items), items)
	}
}

// --- ideParseVSCodeRecent tests ---

func TestIdeParseVSCodeRecent_ExtractsFilePaths(t *testing.T) {
	data := []byte(`{
		"openedPathsList": {
			"entries": [
				"file:///home/user/project1",
				"file:///tmp/test-workspace"
			]
		}
	}`)
	paths := ideParseVSCodeRecent(data)
	if len(paths) == 0 {
		t.Fatal("expected at least one path from openedPathsList")
	}
	found := false
	for _, p := range paths {
		if strings.Contains(p, "project1") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected project1 in paths, got %v", paths)
	}
}

func TestIdeParseVSCodeRecent_IgnoresUnrelatedKeys(t *testing.T) {
	data := []byte(`{
		"editor.fontSize": 14,
		"telemetry.enabled": false,
		"unrelated": "/some/path"
	}`)
	// "unrelated" key doesn't match recent/opened/workspace/folder
	paths := ideParseVSCodeRecent(data)
	for _, p := range paths {
		if strings.Contains(p, "/some/path") {
			t.Errorf("path from unrelated key should not be included: %q", p)
		}
	}
}

func TestIdeParseVSCodeRecent_Deduplicates(t *testing.T) {
	data := []byte(`{
		"recentWorkspaces": ["file:///home/user/proj", "file:///home/user/proj"],
		"openedFolders": ["file:///home/user/proj"]
	}`)
	paths := ideParseVSCodeRecent(data)
	count := 0
	for _, p := range paths {
		if strings.Contains(p, "/home/user/proj") {
			count++
		}
	}
	if count > 1 {
		t.Errorf("duplicate path should appear only once, got %d times", count)
	}
}

// --- ideExtractPathsFromString tests ---

func TestIdeExtractPathsFromString_FileURIWithSpaceEncoding(t *testing.T) {
	paths := ideExtractPathsFromString("file:///home/user/my%20project")
	if len(paths) == 0 {
		t.Fatal("expected path")
	}
	if paths[0] != "/home/user/my project" {
		t.Errorf("path = %q, want /home/user/my project", paths[0])
	}
}

func TestIdeExtractPathsFromString_PlainUnixPath(t *testing.T) {
	paths := ideExtractPathsFromString("/etc/fstab")
	if len(paths) == 0 {
		t.Fatal("expected path for /etc/fstab")
	}
	if paths[0] != "/etc/fstab" {
		t.Errorf("path = %q, want /etc/fstab", paths[0])
	}
}

func TestIdeExtractPathsFromString_ShortStringIgnored(t *testing.T) {
	paths := ideExtractPathsFromString("/a")
	if len(paths) != 0 {
		t.Errorf("short path should be ignored, got %v", paths)
	}
}

func TestIdeExtractPathsFromString_NoPath(t *testing.T) {
	paths := ideExtractPathsFromString("just some text")
	if len(paths) != 0 {
		t.Errorf("non-path string should return no paths, got %v", paths)
	}
}

func TestIdeExtractPathsFromString_FileURITrailingCharsStripped(t *testing.T) {
	paths := ideExtractPathsFromString(`file:///home/user/project",}`)
	if len(paths) == 0 {
		t.Fatal("expected path")
	}
	if strings.ContainsAny(paths[0], `",}`) {
		t.Errorf("trailing chars not stripped: %q", paths[0])
	}
}

// --- ideCollectPaths tests ---

func TestIdeCollectPaths_String(t *testing.T) {
	var paths []string
	seen := make(map[string]bool)
	ideCollectPaths("/home/user/code", &paths, seen)
	if len(paths) != 1 || paths[0] != "/home/user/code" {
		t.Errorf("paths = %v, want [/home/user/code]", paths)
	}
}

func TestIdeCollectPaths_Deduplication(t *testing.T) {
	var paths []string
	seen := make(map[string]bool)
	ideCollectPaths("/home/user/code", &paths, seen)
	ideCollectPaths("/home/user/code", &paths, seen) // duplicate
	if len(paths) != 1 {
		t.Errorf("duplicate paths: got %d, want 1", len(paths))
	}
}

func TestIdeCollectPaths_SliceOfStrings(t *testing.T) {
	var paths []string
	seen := make(map[string]bool)
	val := []interface{}{"/home/user/proj1", "/home/user/proj2"}
	ideCollectPaths(val, &paths, seen)
	if len(paths) != 2 {
		t.Errorf("paths count = %d, want 2", len(paths))
	}
}

func TestIdeCollectPaths_NestedMap(t *testing.T) {
	var paths []string
	seen := make(map[string]bool)
	val := map[string]interface{}{
		"uri": "file:///home/user/nested-project",
	}
	ideCollectPaths(val, &paths, seen)
	found := false
	for _, p := range paths {
		if strings.Contains(p, "nested-project") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("nested path not found in %v", paths)
	}
}
