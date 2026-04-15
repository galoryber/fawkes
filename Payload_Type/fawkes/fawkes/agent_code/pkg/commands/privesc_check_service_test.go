//go:build linux

package commands

import (
	"strings"
	"testing"
)

func TestExtractScriptPaths_CronLines(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected []string
	}{
		{
			"simple cron job",
			"*/5 * * * * root /usr/local/bin/backup.sh",
			[]string{"/usr/local/bin/backup.sh"},
		},
		{
			"multiple paths",
			"0 3 * * * root /usr/bin/find /var/log -name '*.gz' -delete",
			[]string{"/usr/bin/find", "/var/log"},
		},
		{
			"skip /dev/ paths",
			"0 * * * * root /usr/bin/script > /dev/null 2>&1",
			[]string{"/usr/bin/script"},
		},
		{
			"redirect target included",
			"0 3 * * * root /usr/bin/cmd > /var/log/cmd.log",
			[]string{"/usr/bin/cmd", "/var/log/cmd.log"}, // extractScriptPaths doesn't parse shell redirects
		},
		{
			"no paths",
			"SHELL=/bin/bash",
			nil,
		},
		{
			"empty line",
			"",
			nil,
		},
		{
			"variable assignment",
			"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
			nil,
		},
		{
			"run-parts",
			"0 * * * * root /usr/bin/run-parts /etc/cron.hourly",
			[]string{"/usr/bin/run-parts", "/etc/cron.hourly"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			paths := extractScriptPaths(tc.line)
			if tc.expected == nil {
				if len(paths) != 0 {
					t.Errorf("expected no paths, got %v", paths)
				}
				return
			}
			if len(paths) != len(tc.expected) {
				t.Fatalf("got %d paths, want %d: %v vs %v", len(paths), len(tc.expected), paths, tc.expected)
			}
			for i, p := range paths {
				if p != tc.expected[i] {
					t.Errorf("path[%d] = %q, want %q", i, p, tc.expected[i])
				}
			}
		})
	}
}

func TestExtractScriptPaths_DevNullFilter(t *testing.T) {
	paths := extractScriptPaths("*/5 * * * * root /usr/bin/check > /dev/null 2>/dev/stderr")
	for _, p := range paths {
		if strings.HasPrefix(p, "/dev/") {
			t.Errorf("should not return /dev/ paths, got %q", p)
		}
	}
}

func TestNFSNoRootSquashDetection(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		hasNoSquash bool
	}{
		{
			"no_root_squash present",
			"/home/share 192.168.1.0/24(rw,no_root_squash,sync)",
			true,
		},
		{
			"root_squash (safe)",
			"/data 10.0.0.0/8(rw,root_squash,sync)",
			false,
		},
		{
			"default options",
			"/export *(rw,sync)",
			false,
		},
		{
			"comment",
			"# /home/share 192.168.1.0/24(rw,no_root_squash)",
			false, // should be filtered as comment
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := strings.TrimSpace(tc.line)
			if line == "" || strings.HasPrefix(line, "#") {
				if tc.hasNoSquash {
					t.Error("expected no_root_squash but line was filtered")
				}
				return
			}
			hasNoSquash := strings.Contains(line, "no_root_squash")
			if hasNoSquash != tc.hasNoSquash {
				t.Errorf("got hasNoSquash=%v, want %v", hasNoSquash, tc.hasNoSquash)
			}
		})
	}
}

func TestSystemdUnitFileFilter(t *testing.T) {
	// Only .service and .timer files should be checked
	names := []string{
		"myapp.service",
		"backup.timer",
		"myapp.socket",
		"network.target",
		"README",
		"myapp.mount",
	}
	var matched []string
	for _, name := range names {
		if strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".timer") {
			matched = append(matched, name)
		}
	}
	if len(matched) != 2 {
		t.Errorf("expected 2 matched (service + timer), got %d: %v", len(matched), matched)
	}
}
