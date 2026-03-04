//go:build windows
// +build windows

package commands

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// regSearchResult holds a single registry search match (used by reg -action search).
type regSearchResult struct {
	KeyPath   string `json:"key_path"`
	ValueName string `json:"value_name,omitempty"`
	ValueData string `json:"value_data,omitempty"`
}

// regSearchRecursive searches registry keys and values recursively for a pattern.
func regSearchRecursive(hive registry.Key, path, pattern string, depth, maxDepth, maxResults int, results *[]regSearchResult) {
	if depth >= maxDepth || len(*results) >= maxResults {
		return
	}

	key, err := registry.OpenKey(hive, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()

	keyLower := strings.ToLower(path)
	if strings.Contains(keyLower, pattern) && len(*results) < maxResults {
		*results = append(*results, regSearchResult{
			KeyPath: path,
		})
	}

	valueNames, err := key.ReadValueNames(-1)
	if err == nil {
		for _, name := range valueNames {
			if len(*results) >= maxResults {
				return
			}
			nameLower := strings.ToLower(name)
			dataStr := regSearchReadValue(key, name)
			dataLower := strings.ToLower(dataStr)

			if strings.Contains(nameLower, pattern) || strings.Contains(dataLower, pattern) {
				*results = append(*results, regSearchResult{
					KeyPath:   path,
					ValueName: name,
					ValueData: dataStr,
				})
			}
		}
	}

	subKeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return
	}

	for _, sub := range subKeys {
		if len(*results) >= maxResults {
			return
		}
		subPath := path + `\` + sub
		regSearchRecursive(hive, subPath, pattern, depth+1, maxDepth, maxResults, results)
	}
}
