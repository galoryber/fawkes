package commands

import (
	"strings"
	"testing"
)

// --- ideMatchesAny ---

func TestIdeMatchesAny_Match(t *testing.T) {
	if !ideMatchesAny("ms-vscode-remote.remote-ssh", "remote", "ssh") {
		t.Error("expected match for 'remote' or 'ssh'")
	}
}

func TestIdeMatchesAny_NoMatch(t *testing.T) {
	if ideMatchesAny("golang.go", "python", "java") {
		t.Error("expected no match")
	}
}

func TestIdeMatchesAny_EmptyPatterns(t *testing.T) {
	if ideMatchesAny("anything") {
		t.Error("expected no match with no patterns")
	}
}

// --- ideCategorizExtensions ---

func TestIdeCategorizExtensions_Security(t *testing.T) {
	exts := []string{
		"ms-azuretools.vscode-docker-1.25.0",
		"hashicorp.terraform-2.30.0",
		"snyk-security.snyk-vulnerability-scanner-1.0.0",
	}
	security, remote, other := ideCategorizExtensions(exts)
	if len(security) != 3 {
		t.Errorf("expected 3 security extensions, got %d: %v", len(security), security)
	}
	if len(remote) != 0 {
		t.Errorf("expected 0 remote extensions, got %d", len(remote))
	}
	if len(other) != 0 {
		t.Errorf("expected 0 other extensions, got %d", len(other))
	}
}

func TestIdeCategorizExtensions_Remote(t *testing.T) {
	exts := []string{
		"ms-vscode-remote.remote-ssh-0.102.0",
		"ms-vscode-remote.remote-wsl-0.80.0",
		"ms-vscode-remote.remote-containers-0.350.0",
	}
	security, remote, other := ideCategorizExtensions(exts)
	if len(security) != 0 {
		t.Errorf("expected 0 security, got %d", len(security))
	}
	if len(remote) != 3 {
		t.Errorf("expected 3 remote, got %d: %v", len(remote), remote)
	}
	if len(other) != 0 {
		t.Errorf("expected 0 other, got %d", len(other))
	}
}

func TestIdeCategorizExtensions_Mixed(t *testing.T) {
	exts := []string{
		"golang.go-0.40.0",
		"ms-vscode-remote.remote-ssh-0.102.0",
		"hashicorp.terraform-2.30.0",
		"esbenp.prettier-vscode-10.0.0",
	}
	security, remote, other := ideCategorizExtensions(exts)
	if len(security) != 1 {
		t.Errorf("expected 1 security, got %d", len(security))
	}
	if len(remote) != 1 {
		t.Errorf("expected 1 remote, got %d", len(remote))
	}
	if len(other) != 2 {
		t.Errorf("expected 2 other, got %d", len(other))
	}
}

// --- ideExtractInterestingSettings ---

func TestIdeExtractInterestingSettings_Proxy(t *testing.T) {
	settings := map[string]interface{}{
		"http.proxy":          "http://proxy.corp.local:8080",
		"http.proxyStrictSSL": false,
		"editor.fontSize":     14,
	}
	items := ideExtractInterestingSettings(settings)
	if len(items) != 2 {
		t.Errorf("expected 2 items, got %d: %v", len(items), items)
	}
}

func TestIdeExtractInterestingSettings_SensitiveKeys(t *testing.T) {
	settings := map[string]interface{}{
		"myextension.apiToken":     "ghp_abc123def456",
		"custom.password":          "secret123",
		"editor.fontSize":          14,
		"some.api_key":             "AKIA1234567890123456",
		"remote.SSH.remotePlatform": map[string]interface{}{"server1": "linux"},
	}
	items := ideExtractInterestingSettings(settings)
	// Should find: remote.SSH.remotePlatform (interesting key) + 3 sensitive keys
	found := 0
	sensitive := 0
	for _, item := range items {
		if strings.Contains(item, "[SENSITIVE]") {
			sensitive++
		}
		found++
	}
	if sensitive != 3 {
		t.Errorf("expected 3 sensitive items, got %d: %v", sensitive, items)
	}
	if found < 4 {
		t.Errorf("expected at least 4 items, got %d: %v", found, items)
	}
}

func TestIdeExtractInterestingSettings_Empty(t *testing.T) {
	settings := map[string]interface{}{
		"editor.fontSize": 14,
		"editor.tabSize":  4,
	}
	items := ideExtractInterestingSettings(settings)
	if len(items) != 0 {
		t.Errorf("expected 0 items, got %d: %v", len(items), items)
	}
}

// --- ideExtractPathsFromString ---

func TestIdeExtractPathsFromString_FileURI(t *testing.T) {
	s := `file:///home/user/projects/myapp`
	paths := ideExtractPathsFromString(s)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d: %v", len(paths), paths)
	}
	if paths[0] != "/home/user/projects/myapp" {
		t.Errorf("expected /home/user/projects/myapp, got %s", paths[0])
	}
}

func TestIdeExtractPathsFromString_WindowsFileURI(t *testing.T) {
	s := `file:///C:/Users/admin/workspace`
	paths := ideExtractPathsFromString(s)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d: %v", len(paths), paths)
	}
	// Should include the drive letter path
	if !strings.Contains(paths[0], "C:") {
		t.Errorf("expected Windows path with C:, got %s", paths[0])
	}
}

func TestIdeExtractPathsFromString_MultipleURIs(t *testing.T) {
	s := `file:///home/user/project1","file:///home/user/project2`
	paths := ideExtractPathsFromString(s)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(paths), paths)
	}
}

func TestIdeExtractPathsFromString_PlainPath(t *testing.T) {
	s := `/home/user/workspace`
	paths := ideExtractPathsFromString(s)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d: %v", len(paths), paths)
	}
	if paths[0] != "/home/user/workspace" {
		t.Errorf("expected /home/user/workspace, got %s", paths[0])
	}
}

func TestIdeExtractPathsFromString_URLEncoded(t *testing.T) {
	s := `file:///home/user/my%20project`
	paths := ideExtractPathsFromString(s)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d: %v", len(paths), paths)
	}
	if !strings.Contains(paths[0], "my project") {
		t.Errorf("expected decoded space in path, got %s", paths[0])
	}
}

func TestIdeExtractPathsFromString_Short(t *testing.T) {
	paths := ideExtractPathsFromString("ab")
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for short string, got %d", len(paths))
	}
}

// --- ideParseVSCodeRecent ---

func TestIdeParseVSCodeRecent_WithPaths(t *testing.T) {
	data := []byte(`{
		"openedPathsList": {
			"workspaces3": [
				"file:///home/user/project-alpha",
				"file:///home/user/project-beta"
			],
			"files2": [
				"file:///home/user/notes.txt"
			]
		}
	}`)
	paths := ideParseVSCodeRecent(data)
	if len(paths) < 2 {
		t.Errorf("expected at least 2 paths, got %d: %v", len(paths), paths)
	}
}

func TestIdeParseVSCodeRecent_RecentFolders(t *testing.T) {
	data := []byte(`{
		"lastKnownMenubarData": {},
		"recentlyOpened": [
			{"folderUri": "file:///home/dev/api-server"},
			{"folderUri": "file:///home/dev/web-frontend"}
		]
	}`)
	paths := ideParseVSCodeRecent(data)
	if len(paths) < 1 {
		t.Errorf("expected at least 1 path, got %d: %v", len(paths), paths)
	}
}

func TestIdeParseVSCodeRecent_Empty(t *testing.T) {
	data := []byte(`{"editor.fontSize": 14}`)
	paths := ideParseVSCodeRecent(data)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(paths))
	}
}

func TestIdeParseVSCodeRecent_InvalidJSON(t *testing.T) {
	data := []byte(`not json`)
	paths := ideParseVSCodeRecent(data)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for invalid JSON, got %d", len(paths))
	}
}

// --- ideParseJetBrainsRecentXML ---

func TestIdeParseJetBrainsRecentXML_Projects(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<application>
  <component name="RecentProjectsManager">
    <option name="additionalInfo">
      <map>
        <entry key="$USER_HOME$/projects/backend-api">
          <value>
            <RecentProjectMetaInfo>
              <option name="build" value="IU-231.9392.2" />
            </RecentProjectMetaInfo>
          </value>
        </entry>
        <entry key="/opt/workspace/frontend">
          <value>
            <RecentProjectMetaInfo>
              <option name="build" value="IU-231.9392.2" />
            </RecentProjectMetaInfo>
          </value>
        </entry>
      </map>
    </option>
  </component>
</application>`
	projects := ideParseJetBrainsRecentXML(xml)
	if len(projects) < 2 {
		t.Errorf("expected at least 2 projects, got %d: %v", len(projects), projects)
	}

	// Check that $USER_HOME$ is expanded
	foundHome := false
	for _, p := range projects {
		if strings.Contains(p, "~/projects/backend-api") {
			foundHome = true
		}
	}
	if !foundHome {
		t.Errorf("expected $USER_HOME$ to be expanded to ~: %v", projects)
	}
}

func TestIdeParseJetBrainsRecentXML_WindowsPaths(t *testing.T) {
	xml := `<entry key="C:\Users\admin\IdeaProjects\spring-boot-app">`
	projects := ideParseJetBrainsRecentXML(xml)
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d: %v", len(projects), projects)
	}
	if !strings.Contains(projects[0], `C:\Users`) {
		t.Errorf("expected Windows path, got %s", projects[0])
	}
}

func TestIdeParseJetBrainsRecentXML_Empty(t *testing.T) {
	projects := ideParseJetBrainsRecentXML("")
	if len(projects) != 0 {
		t.Errorf("expected 0 projects, got %d", len(projects))
	}
}

// --- ideParseJetBrainsDataSources ---

func TestIdeParseJetBrainsDataSources_JDBC(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <component name="DataSourceManagerImpl">
    <data-source name="Production DB" uuid="abc-123">
      <option name="url" value="jdbc:postgresql://db.internal:5432/production" />
      <option name="user" value="app_user" />
    </data-source>
    <data-source name="Staging MySQL" uuid="def-456">
      <option name="url" value="jdbc:mysql://staging-db.corp.local:3306/staging" />
      <option name="user" value="stg_user" />
    </data-source>
  </component>
</project>`
	sources := ideParseJetBrainsDataSources(xml)
	if len(sources) < 2 {
		t.Errorf("expected at least 2 data sources, got %d: %v", len(sources), sources)
	}

	// Check that URLs are captured
	foundPostgres := false
	foundMySQL := false
	for _, s := range sources {
		if strings.Contains(s, "postgresql") {
			foundPostgres = true
		}
		if strings.Contains(s, "mysql") {
			foundMySQL = true
		}
	}
	if !foundPostgres {
		t.Error("expected PostgreSQL connection")
	}
	if !foundMySQL {
		t.Error("expected MySQL connection")
	}
}

func TestIdeParseJetBrainsDataSources_Empty(t *testing.T) {
	sources := ideParseJetBrainsDataSources("<project></project>")
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}
}

// --- ideParseJetBrainsServers ---

func TestIdeParseJetBrainsServers_WebServers(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <component name="WebServers">
    <option name="servers">
      <webServer name="Production Server" host="prod.example.com" />
      <webServer name="Dev Server" host="dev.internal.corp" />
    </option>
  </component>
</project>`
	servers := ideParseJetBrainsServers(xml)
	if len(servers) < 2 {
		t.Errorf("expected at least 2 servers, got %d: %v", len(servers), servers)
	}
}

func TestIdeParseJetBrainsServers_Empty(t *testing.T) {
	servers := ideParseJetBrainsServers("<project></project>")
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

// --- ideExtractXMLAttr ---

func TestIdeExtractXMLAttr_Found(t *testing.T) {
	line := `<option name="url" value="jdbc:postgresql://localhost:5432/db" />`
	val := ideExtractXMLAttr(line, "value")
	if val != "jdbc:postgresql://localhost:5432/db" {
		t.Errorf("expected JDBC URL, got %s", val)
	}
}

func TestIdeExtractXMLAttr_Name(t *testing.T) {
	line := `<option name="url" value="test" />`
	val := ideExtractXMLAttr(line, "name")
	if val != "url" {
		t.Errorf("expected 'url', got %s", val)
	}
}

func TestIdeExtractXMLAttr_NotFound(t *testing.T) {
	line := `<option name="url" />`
	val := ideExtractXMLAttr(line, "value")
	if val != "" {
		t.Errorf("expected empty string, got %s", val)
	}
}

func TestIdeExtractXMLAttr_EmptyLine(t *testing.T) {
	val := ideExtractXMLAttr("", "name")
	if val != "" {
		t.Errorf("expected empty string, got %s", val)
	}
}

func TestIdeExtractXMLAttr_UnclosedQuote(t *testing.T) {
	line := `<option value="no-closing-quote`
	val := ideExtractXMLAttr(line, "value")
	if val != "" {
		t.Errorf("expected empty for unclosed quote, got %q", val)
	}
}

func TestIdeParseJetBrainsServers_ValueAttr(t *testing.T) {
	xml := `<component>
  <server name="MyServer" />
  <option url="http://api.example.com" value="http://api.example.com" />
</component>`
	servers := ideParseJetBrainsServers(xml)
	if len(servers) == 0 {
		t.Error("expected at least 1 server from value attr")
	}
}

func TestIdeParseJetBrainsServers_NoName(t *testing.T) {
	xml := `<config>
  <option host="standalone.example.com" />
</config>`
	servers := ideParseJetBrainsServers(xml)
	if len(servers) == 0 {
		t.Error("expected at least 1 server")
	}
	if len(servers) > 0 && servers[0] != "standalone.example.com" {
		t.Errorf("expected plain hostname, got %q", servers[0])
	}
}

// --- ideVSCodeConfigDirs ---

func TestIdeVSCodeConfigDirs_NotEmpty(t *testing.T) {
	dirs := ideVSCodeConfigDirs("/home/testuser")
	if len(dirs) == 0 {
		t.Error("expected at least one config directory")
	}
}

// --- ideJetBrainsConfigBase ---

func TestIdeJetBrainsConfigBase_NotEmpty(t *testing.T) {
	base := ideJetBrainsConfigBase("/home/testuser")
	if base == "" {
		t.Error("expected non-empty config base")
	}
	if !strings.Contains(base, "JetBrains") {
		t.Errorf("expected 'JetBrains' in path, got %s", base)
	}
}

// --- ideDiscoverJetBrainsProducts ---

func TestIdeDiscoverJetBrainsProducts_NonexistentDir(t *testing.T) {
	products := ideDiscoverJetBrainsProducts("/nonexistent/path/JetBrains")
	if len(products) != 0 {
		t.Errorf("expected 0 products for nonexistent dir, got %d", len(products))
	}
}
