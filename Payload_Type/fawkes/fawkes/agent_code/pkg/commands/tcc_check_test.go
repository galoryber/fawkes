package commands

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestTCCServiceNames(t *testing.T) {
	// Verify all well-known services have mappings
	wellKnown := []string{
		"kTCCServiceCamera",
		"kTCCServiceMicrophone",
		"kTCCServiceScreenCapture",
		"kTCCServiceSystemPolicyAllFiles",
		"kTCCServiceAccessibility",
		"kTCCServiceAddressBook",
		"kTCCServiceCalendar",
		"kTCCServicePhotos",
		"kTCCServiceReminders",
		"kTCCServiceLocation",
		"kTCCServiceListenEvent",
		"kTCCServiceAppleEvents",
		"kTCCServiceDeveloperTool",
		"kTCCServiceEndpointSecurityClient",
	}

	for _, svc := range wellKnown {
		if _, ok := tccServiceNames[svc]; !ok {
			t.Errorf("missing mapping for well-known service: %s", svc)
		}
	}
}

func TestTCCServiceNamesReadable(t *testing.T) {
	// Verify mapped names are human-readable (not just repeating the key)
	for key, name := range tccServiceNames {
		if name == "" {
			t.Errorf("empty name for service %s", key)
		}
		if strings.HasPrefix(name, "kTCC") {
			t.Errorf("service name looks like a key, not human-readable: %s -> %s", key, name)
		}
	}
}

func TestTCCAuthValueStr(t *testing.T) {
	tests := []struct {
		value int
		want  string
	}{
		{0, "Denied"},
		{1, "Unknown"},
		{2, "Allowed"},
		{3, "Limited"},
		{99, "Unknown(99)"},
		{-1, "Unknown(-1)"},
	}

	for _, tt := range tests {
		got := tccAuthValueStr(tt.value)
		if got != tt.want {
			t.Errorf("tccAuthValueStr(%d) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestTCCAuthReasonStr(t *testing.T) {
	tests := []struct {
		value int
		want  string
	}{
		{0, "Error"},
		{1, "User Consent"},
		{2, "User Set"},
		{3, "System Set"},
		{4, "Service Policy"},
		{5, "MDM Policy"},
		{6, "Override Policy"},
		{7, "Missing Usage String"},
		{8, "Prompt Timeout"},
		{9, "Preflight Unknown"},
		{10, "Entitled"},
		{11, "App Type Policy"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		got := tccAuthReasonStr(tt.value)
		if got != tt.want {
			t.Errorf("tccAuthReasonStr(%d) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestTCCClientTypeStr(t *testing.T) {
	tests := []struct {
		value int
		want  string
	}{
		{0, "Bundle ID"},
		{1, "Absolute Path"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		got := tccClientTypeStr(tt.value)
		if got != tt.want {
			t.Errorf("tccClientTypeStr(%d) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestFormatTCCOutput(t *testing.T) {
	entries := []tccEntry{
		{
			Service:     "kTCCServiceCamera",
			ServiceName: "Camera",
			Client:      "com.apple.Terminal",
			ClientType:  0,
			AuthValue:   2,
			AuthReason:  1,
			Source:      "user",
		},
		{
			Service:     "kTCCServiceMicrophone",
			ServiceName: "Microphone",
			Client:      "com.zoom.us",
			ClientType:  0,
			AuthValue:   2,
			AuthReason:  1,
			Source:      "user",
		},
		{
			Service:     "kTCCServiceScreenCapture",
			ServiceName: "Screen Recording",
			Client:      "com.apple.Terminal",
			ClientType:  0,
			AuthValue:   0,
			AuthReason:  1,
			Source:      "system",
		},
	}

	output := formatTCCOutput(entries, "", "/Users/test/Library/TCC.db", "/Library/TCC.db")

	// Check header
	if !strings.Contains(output, "macOS TCC Permissions") {
		t.Error("output missing header")
	}

	// Check record count
	if !strings.Contains(output, "Records:   3") {
		t.Error("output should show 3 records")
	}

	// Check service sections
	if !strings.Contains(output, "--- Camera ---") {
		t.Error("output missing Camera section")
	}
	if !strings.Contains(output, "--- Microphone ---") {
		t.Error("output missing Microphone section")
	}
	if !strings.Contains(output, "--- Screen Recording ---") {
		t.Error("output missing Screen Recording section")
	}

	// Check allowed entries
	if !strings.Contains(output, "[Allowed] com.apple.Terminal") {
		t.Error("output missing allowed Terminal entry")
	}
	if !strings.Contains(output, "[Denied] com.apple.Terminal") {
		t.Error("output missing denied Terminal entry for screen recording")
	}

	// Check summary section
	if !strings.Contains(output, "Allowed Permissions Summary") {
		t.Error("output missing allowed permissions summary")
	}

	// Check source annotations
	if !strings.Contains(output, "user)") {
		t.Error("output should show 'user' source")
	}
	if !strings.Contains(output, "system)") {
		t.Error("output should show 'system' source")
	}
}

func TestFormatTCCOutputWithFilter(t *testing.T) {
	entries := []tccEntry{
		{
			Service:     "kTCCServiceCamera",
			ServiceName: "Camera",
			Client:      "com.test.app",
			ClientType:  0,
			AuthValue:   2,
			AuthReason:  1,
			Source:      "user",
		},
	}

	output := formatTCCOutput(entries, "Camera", "/Users/test/Library/TCC.db", "/Library/TCC.db")

	if !strings.Contains(output, "Filter:    Camera") {
		t.Error("output should show the filter when specified")
	}
}

func TestFormatTCCOutputNoAllowed(t *testing.T) {
	entries := []tccEntry{
		{
			Service:     "kTCCServiceCamera",
			ServiceName: "Camera",
			Client:      "com.test.app",
			ClientType:  0,
			AuthValue:   0,
			AuthReason:  1,
			Source:      "user",
		},
	}

	output := formatTCCOutput(entries, "", "/path/user.db", "/path/system.db")

	if !strings.Contains(output, "no allowed permissions found") {
		t.Error("output should indicate no allowed permissions when all are denied")
	}
}

func TestFormatTCCOutputGroupOrder(t *testing.T) {
	// Entries in mixed order — output should group by service
	entries := []tccEntry{
		{ServiceName: "Camera", Client: "app1", AuthValue: 2, AuthReason: 1, Source: "user"},
		{ServiceName: "Microphone", Client: "app2", AuthValue: 2, AuthReason: 1, Source: "user"},
		{ServiceName: "Camera", Client: "app3", AuthValue: 0, AuthReason: 1, Source: "user"},
	}

	output := formatTCCOutput(entries, "", "/path/u.db", "/path/s.db")

	// Camera section should appear before Microphone (insertion order)
	cameraIdx := strings.Index(output, "--- Camera ---")
	micIdx := strings.Index(output, "--- Microphone ---")
	if cameraIdx == -1 || micIdx == -1 {
		t.Fatal("missing section headers")
	}
	if cameraIdx > micIdx {
		t.Error("Camera section should appear before Microphone (first-seen order)")
	}
}

func TestFormatTCCOutputPathBasedClient(t *testing.T) {
	entries := []tccEntry{
		{
			Service:     "kTCCServiceSystemPolicyAllFiles",
			ServiceName: "Full Disk Access",
			Client:      "/usr/sbin/sshd",
			ClientType:  1,
			AuthValue:   2,
			AuthReason:  3,
			Source:      "system",
		},
	}

	output := formatTCCOutput(entries, "", "/path/u.db", "/path/s.db")

	if !strings.Contains(output, "Absolute Path") {
		t.Error("output should show 'Absolute Path' for client_type=1")
	}
	if !strings.Contains(output, "/usr/sbin/sshd") {
		t.Error("output should include the full path of the client")
	}
}

// createTestTCCDB creates a temporary SQLite database mimicking the TCC schema.
func createTestTCCDB(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "TCC.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE access (
		service TEXT NOT NULL,
		client TEXT NOT NULL,
		client_type INTEGER NOT NULL,
		auth_value INTEGER NOT NULL DEFAULT 0,
		auth_reason INTEGER NOT NULL DEFAULT 0,
		auth_version INTEGER NOT NULL DEFAULT 1,
		csreq BLOB,
		policy_id INTEGER,
		indirect_object_identifier_type INTEGER,
		indirect_object_identifier TEXT DEFAULT 'UNUSED',
		indirect_object_code_identity BLOB,
		flags INTEGER,
		last_modified INTEGER NOT NULL DEFAULT 0
	)`)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	// Insert test data
	insertData := []struct {
		service    string
		client     string
		clientType int
		authValue  int
		authReason int
	}{
		{"kTCCServiceCamera", "com.apple.Terminal", 0, 2, 1},
		{"kTCCServiceMicrophone", "com.zoom.us", 0, 2, 1},
		{"kTCCServiceScreenCapture", "com.apple.Terminal", 0, 0, 1},
		{"kTCCServiceSystemPolicyAllFiles", "/usr/sbin/sshd", 1, 2, 3},
		{"kTCCServiceAccessibility", "com.apple.Terminal", 0, 2, 1},
		{"kTCCServiceCamera", "com.zoom.us", 0, 2, 1},
	}

	for _, d := range insertData {
		_, err := db.Exec("INSERT INTO access (service, client, client_type, auth_value, auth_reason) VALUES (?, ?, ?, ?, ?)",
			d.service, d.client, d.clientType, d.authValue, d.authReason)
		if err != nil {
			t.Fatalf("failed to insert test data: %v", err)
		}
	}

	return dbPath
}

func TestReadTCCDatabase(t *testing.T) {
	dbPath := createTestTCCDB(t)

	entries, err := readTCCDatabase(dbPath, "", "user")
	if err != nil {
		t.Fatalf("readTCCDatabase failed: %v", err)
	}

	if len(entries) != 6 {
		t.Errorf("expected 6 entries, got %d", len(entries))
	}

	// Verify entries have source set
	for _, e := range entries {
		if e.Source != "user" {
			t.Errorf("expected source 'user', got %q", e.Source)
		}
	}

	// Verify service names are resolved
	cameraFound := false
	for _, e := range entries {
		if e.Service == "kTCCServiceCamera" && e.ServiceName == "Camera" {
			cameraFound = true
			break
		}
	}
	if !cameraFound {
		t.Error("expected Camera service name resolution")
	}
}

func TestReadTCCDatabaseWithFilter(t *testing.T) {
	dbPath := createTestTCCDB(t)

	entries, err := readTCCDatabase(dbPath, "Camera", "user")
	if err != nil {
		t.Fatalf("readTCCDatabase with filter failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 Camera entries, got %d", len(entries))
	}

	for _, e := range entries {
		if !strings.Contains(e.Service, "Camera") {
			t.Errorf("filtered entry has wrong service: %s", e.Service)
		}
	}
}

func TestReadTCCDatabaseFilterCaseInsensitive(t *testing.T) {
	dbPath := createTestTCCDB(t)

	// The LIKE operator in SQLite is case-insensitive for ASCII
	entries, err := readTCCDatabase(dbPath, "camera", "user")
	if err != nil {
		t.Fatalf("readTCCDatabase failed: %v", err)
	}

	// SQLite LIKE is case-insensitive for ASCII, so "camera" should match "Camera"
	if len(entries) != 2 {
		t.Errorf("expected 2 entries with case-insensitive filter, got %d", len(entries))
	}
}

func TestReadTCCDatabaseNonexistent(t *testing.T) {
	_, err := readTCCDatabase("/nonexistent/path/TCC.db", "", "user")
	if err == nil {
		t.Error("expected error for nonexistent database")
	}
}

func TestReadTCCDatabaseEmptyResult(t *testing.T) {
	dbPath := createTestTCCDB(t)

	entries, err := readTCCDatabase(dbPath, "NonexistentService", "user")
	if err != nil {
		t.Fatalf("readTCCDatabase failed: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nonexistent service, got %d", len(entries))
	}
}

func TestReadTCCDatabaseUnknownService(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "TCC.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE access (
		service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER, auth_reason INTEGER
	)`)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	_, err = db.Exec("INSERT INTO access VALUES (?, ?, ?, ?, ?)",
		"kTCCServiceUnknownNew", "com.test.app", 0, 2, 1)
	if err != nil {
		t.Fatalf("failed to insert: %v", err)
	}
	db.Close()

	entries, err := readTCCDatabase(dbPath, "", "user")
	if err != nil {
		t.Fatalf("readTCCDatabase failed: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// Unknown service should use raw key as service name
	if entries[0].ServiceName != "kTCCServiceUnknownNew" {
		t.Errorf("unknown service should use raw key as name, got: %s", entries[0].ServiceName)
	}
}

func TestTCCDBPaths(t *testing.T) {
	userDB, systemDB := tccDBPaths()

	// System DB should always be this path
	if systemDB != "/Library/Application Support/com.apple.TCC/TCC.db" {
		t.Errorf("unexpected system DB path: %s", systemDB)
	}

	// User DB should contain the home directory
	if !strings.Contains(userDB, "Library/Application Support/com.apple.TCC/TCC.db") {
		t.Errorf("user DB path missing expected suffix: %s", userDB)
	}

	// User DB should not equal system DB
	if userDB == systemDB {
		t.Error("user and system DB paths should differ")
	}
}

func TestReadTCCDatabaseInvalidDB(t *testing.T) {
	// Create a file that isn't a valid SQLite database
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "TCC.db")
	if err := os.WriteFile(dbPath, []byte("not a database"), 0644); err != nil {
		t.Fatalf("failed to write fake db: %v", err)
	}

	_, err := readTCCDatabase(dbPath, "", "user")
	if err == nil {
		t.Error("expected error for invalid database file")
	}
}

func TestTCCServiceNamesCoverage(t *testing.T) {
	// Ensure we have mappings for all critical security services
	critical := map[string]string{
		"kTCCServiceCamera":                   "Camera",
		"kTCCServiceMicrophone":               "Microphone",
		"kTCCServiceScreenCapture":            "Screen Recording",
		"kTCCServiceSystemPolicyAllFiles":     "Full Disk Access",
		"kTCCServiceAccessibility":            "Accessibility",
		"kTCCServiceListenEvent":              "Input Monitoring",
		"kTCCServiceEndpointSecurityClient":   "Endpoint Security",
		"kTCCServiceDeveloperTool":            "Developer Tools",
	}

	for key, expectedName := range critical {
		got, ok := tccServiceNames[key]
		if !ok {
			t.Errorf("missing critical service mapping: %s", key)
			continue
		}
		if got != expectedName {
			t.Errorf("service %s: got name %q, want %q", key, got, expectedName)
		}
	}
}

func TestFormatTCCOutputMultipleClientsPerService(t *testing.T) {
	entries := []tccEntry{
		{ServiceName: "Camera", Client: "com.apple.Terminal", AuthValue: 2, AuthReason: 1, Source: "user"},
		{ServiceName: "Camera", Client: "com.zoom.us", AuthValue: 2, AuthReason: 1, Source: "user"},
		{ServiceName: "Camera", Client: "com.google.Chrome", AuthValue: 0, AuthReason: 1, Source: "user"},
	}

	output := formatTCCOutput(entries, "", "/path/u.db", "/path/s.db")

	// Should show Camera section once, with all 3 clients
	count := strings.Count(output, "--- Camera ---")
	if count != 1 {
		t.Errorf("Camera section should appear exactly once, appeared %d times", count)
	}

	// All clients should be present
	for _, client := range []string{"com.apple.Terminal", "com.zoom.us", "com.google.Chrome"} {
		if !strings.Contains(output, client) {
			t.Errorf("output missing client: %s", client)
		}
	}

	// Summary should list only the 2 allowed ones
	summaryIdx := strings.Index(output, "Allowed Permissions Summary")
	if summaryIdx == -1 {
		t.Fatal("missing summary section")
	}
	summary := output[summaryIdx:]
	if !strings.Contains(summary, "com.apple.Terminal") {
		t.Error("summary missing allowed Terminal")
	}
	if !strings.Contains(summary, "com.zoom.us") {
		t.Error("summary missing allowed Zoom")
	}
	if strings.Contains(summary, "com.google.Chrome") {
		t.Error("summary should not include denied Chrome")
	}
}
