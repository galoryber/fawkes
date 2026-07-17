package commands

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// createTempDB creates a SQLite database with the given schema and returns its path.
func createTempDB(t *testing.T, schema string) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return dbPath
}

// --- Chrome History SQL Query Tests ---

func TestChromeHistoryQuery(t *testing.T) {
	schema := `CREATE TABLE urls (
		id INTEGER PRIMARY KEY,
		url TEXT,
		title TEXT,
		visit_count INTEGER,
		last_visit_time INTEGER
	)`
	dbPath := createTempDB(t, schema)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Chrome epoch: microseconds since 1601-01-01
	// 2024-01-15 12:00:00 UTC = 13349793600000000
	chromeTime := int64(13349793600000000)
	_, err = db.Exec(`INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES
		('https://example.com', 'Example Site', 5, ?),
		('https://github.com', 'GitHub', 100, ?),
		('https://empty-title.com', '', 1, ?)`,
		chromeTime, chromeTime-1000000, chromeTime-2000000)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type entry struct {
		URL, Title string
		VisitCount int
		LastVisit  int64
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.URL, &e.Title, &e.VisitCount, &e.LastVisit); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].URL != "https://example.com" {
		t.Errorf("first entry URL = %q", entries[0].URL)
	}
	if entries[0].VisitCount != 5 {
		t.Errorf("first entry visit count = %d", entries[0].VisitCount)
	}
	if chromeTimeToString(entries[0].LastVisit) != "2024-01-15 12:00:00" {
		t.Errorf("time conversion = %q", chromeTimeToString(entries[0].LastVisit))
	}
	if entries[2].Title != "" {
		t.Errorf("empty title should be empty string, got %q", entries[2].Title)
	}
}

func TestChromeHistoryQuery_Empty(t *testing.T) {
	schema := `CREATE TABLE urls (
		id INTEGER PRIMARY KEY,
		url TEXT,
		title TEXT,
		visit_count INTEGER,
		last_visit_time INTEGER
	)`
	dbPath := createTempDB(t, schema)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 entries from empty db, got %d", count)
	}
}

// --- Firefox History SQL Query Tests ---

func TestFirefoxHistoryQuery(t *testing.T) {
	schema := `CREATE TABLE moz_places (
		id INTEGER PRIMARY KEY,
		url TEXT,
		title TEXT,
		visit_count INTEGER,
		last_visit_date INTEGER
	)`
	dbPath := createTempDB(t, schema)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Firefox PRTime: microseconds since Unix epoch
	// 2024-01-15 12:00:00 UTC = 1705320000000000
	ffTime := int64(1705320000000000)
	_, err = db.Exec(`INSERT INTO moz_places (url, title, visit_count, last_visit_date) VALUES
		('https://mozilla.org', 'Mozilla', 10, ?),
		('https://developer.mozilla.org', 'MDN Web Docs', 50, ?),
		('https://visited-no-title.com', NULL, 3, ?)`,
		ffTime, ffTime-1000000, ffTime-2000000)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query("SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE visit_count > 0 ORDER BY last_visit_date DESC LIMIT 500")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type entry struct {
		URL   string
		Title sql.NullString
		Visits int
		Time   int64
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.URL, &e.Title, &e.Visits, &e.Time); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].URL != "https://mozilla.org" {
		t.Errorf("first entry URL = %q", entries[0].URL)
	}
	if firefoxTimeToString(entries[0].Time) != "2024-01-15 12:00:00" {
		t.Errorf("time conversion = %q", firefoxTimeToString(entries[0].Time))
	}
}

// --- Chrome Autofill SQL Query Tests ---

func TestChromeAutofillQuery(t *testing.T) {
	schema := `CREATE TABLE autofill (
		name TEXT,
		value TEXT,
		count INTEGER,
		date_last_used INTEGER
	)`
	dbPath := createTempDB(t, schema)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Autofill date_last_used is seconds since Unix epoch
	unixTime := int64(1705320000)
	_, err = db.Exec(`INSERT INTO autofill (name, value, count, date_last_used) VALUES
		('email', 'user@example.com', 15, ?),
		('name', 'John Doe', 8, ?),
		('phone', '+1-555-0123', 3, ?),
		('cc-number', '4111111111111111', 1, ?)`,
		unixTime, unixTime-86400, unixTime-172800, unixTime-259200)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query("SELECT name, value, count, date_last_used FROM autofill ORDER BY date_last_used DESC LIMIT 500")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type entry struct {
		Name, Value  string
		Count        int
		DateLastUsed int64
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.Name, &e.Value, &e.Count, &e.DateLastUsed); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}

	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	if entries[0].Name != "email" || entries[0].Value != "user@example.com" {
		t.Errorf("first entry = %q/%q", entries[0].Name, entries[0].Value)
	}
	if entries[0].Count != 15 {
		t.Errorf("first entry count = %d, want 15", entries[0].Count)
	}
	if chromeTimeToString(entries[0].DateLastUsed) != "2024-01-15 12:00:00" {
		t.Errorf("time = %q", chromeTimeToString(entries[0].DateLastUsed))
	}
}

// --- Firefox Autofill SQL Query Tests ---

func TestFirefoxAutofillQuery(t *testing.T) {
	schema := `CREATE TABLE moz_formhistory (
		fieldname TEXT,
		value TEXT,
		timesUsed INTEGER,
		lastUsed INTEGER
	)`
	dbPath := createTempDB(t, schema)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ffTime := int64(1705320000000000)
	_, err = db.Exec(`INSERT INTO moz_formhistory (fieldname, value, timesUsed, lastUsed) VALUES
		('searchbar-history', 'golang testing', 5, ?),
		('login-username', 'admin', 3, ?)`,
		ffTime, ffTime-1000000)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query("SELECT fieldname, value, timesUsed, lastUsed FROM moz_formhistory ORDER BY lastUsed DESC LIMIT 500")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type entry struct {
		Field, Value string
		Used         int
		Last         int64
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.Field, &e.Value, &e.Used, &e.Last); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Field != "searchbar-history" {
		t.Errorf("first field = %q", entries[0].Field)
	}
}

// --- Firefox Cookies SQL Query Tests ---

func TestFirefoxCookiesQuery(t *testing.T) {
	schema := `CREATE TABLE moz_cookies (
		id INTEGER PRIMARY KEY,
		host TEXT,
		name TEXT,
		value TEXT,
		path TEXT,
		expiry INTEGER,
		lastAccessed INTEGER,
		isSecure INTEGER,
		isHttpOnly INTEGER
	)`
	dbPath := createTempDB(t, schema)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	expiry := time.Now().Add(24 * time.Hour).Unix()
	lastAccessed := time.Now().Unix() * 1000000
	_, err = db.Exec(`INSERT INTO moz_cookies (host, name, value, path, expiry, lastAccessed, isSecure, isHttpOnly) VALUES
		('.example.com', 'session_id', 'abc123def456', '/', ?, ?, 1, 1),
		('.github.com', '_gh_sess', 'ghtoken_xyz', '/', ?, ?, 0, 1),
		('analytics.example.com', '_ga', 'GA1.2.123.456', '/', ?, ?, 0, 0)`,
		expiry, lastAccessed,
		expiry+86400, lastAccessed-1000000,
		expiry+172800, lastAccessed-2000000)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query("SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies ORDER BY lastAccessed DESC LIMIT 500")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type cookie struct {
		Host, Name, Value, Path string
		Expiry                  int64
		Secure, HTTPOnly        int
	}
	var cookies []cookie
	for rows.Next() {
		var c cookie
		if err := rows.Scan(&c.Host, &c.Name, &c.Value, &c.Path, &c.Expiry, &c.Secure, &c.HTTPOnly); err != nil {
			t.Fatal(err)
		}
		cookies = append(cookies, c)
	}

	if len(cookies) != 3 {
		t.Fatalf("expected 3 cookies, got %d", len(cookies))
	}
	if cookies[0].Host != ".example.com" {
		t.Errorf("first cookie host = %q", cookies[0].Host)
	}
	if cookies[0].Secure != 1 {
		t.Error("first cookie should be secure")
	}
	if cookies[0].HTTPOnly != 1 {
		t.Error("first cookie should be httponly")
	}
	if cookies[2].Secure != 0 || cookies[2].HTTPOnly != 0 {
		t.Error("third cookie should not be secure or httponly")
	}
}

// --- Firefox Bookmarks SQL Query Tests ---

func TestFirefoxBookmarksQuery(t *testing.T) {
	schema := `
	CREATE TABLE moz_places (
		id INTEGER PRIMARY KEY,
		url TEXT
	);
	CREATE TABLE moz_bookmarks (
		id INTEGER PRIMARY KEY,
		type INTEGER,
		fk INTEGER,
		parent INTEGER,
		title TEXT,
		dateAdded INTEGER
	)`
	dbPath := createTempDB(t, schema)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`
		INSERT INTO moz_places (id, url) VALUES (1, 'https://example.com'), (2, 'https://github.com'), (3, 'place:sort=8&maxResults=10');
		INSERT INTO moz_bookmarks (id, type, fk, parent, title, dateAdded) VALUES
			(1, 2, NULL, 0, 'Bookmarks Menu', 1000),
			(2, 2, NULL, 1, 'Work', 2000),
			(3, 1, 1, 1, 'Example', 3000),
			(4, 1, 2, 2, 'GitHub', 4000),
			(5, 1, 3, 1, 'Recent Tags', 5000)`)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query(`
		SELECT b.title, p.url, COALESCE(f.title, '') AS folder
		FROM moz_bookmarks b
		JOIN moz_places p ON b.fk = p.id
		LEFT JOIN moz_bookmarks f ON b.parent = f.id AND f.type = 2
		WHERE b.type = 1 AND p.url NOT LIKE 'place:%'
		ORDER BY b.dateAdded DESC
		LIMIT 500`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type bm struct {
		Title, URL, Folder string
	}
	var bookmarks []bm
	for rows.Next() {
		var b bm
		if err := rows.Scan(&b.Title, &b.URL, &b.Folder); err != nil {
			t.Fatal(err)
		}
		bookmarks = append(bookmarks, b)
	}

	if len(bookmarks) != 2 {
		t.Fatalf("expected 2 bookmarks (place: URL excluded), got %d", len(bookmarks))
	}
	if bookmarks[0].Title != "GitHub" {
		t.Errorf("first bookmark = %q (should be most recent)", bookmarks[0].Title)
	}
	if bookmarks[0].Folder != "Work" {
		t.Errorf("first bookmark folder = %q, want 'Work'", bookmarks[0].Folder)
	}
	if bookmarks[1].Title != "Example" {
		t.Errorf("second bookmark = %q", bookmarks[1].Title)
	}
	if bookmarks[1].Folder != "Bookmarks Menu" {
		t.Errorf("second bookmark folder = %q", bookmarks[1].Folder)
	}
}

// --- Chrome Downloads SQL Query Tests ---

func TestChromeDownloadsQuery(t *testing.T) {
	schema := `CREATE TABLE downloads (
		id INTEGER PRIMARY KEY,
		target_path TEXT,
		tab_url TEXT,
		total_bytes INTEGER,
		start_time INTEGER,
		state INTEGER,
		mime_type TEXT
	)`
	dbPath := createTempDB(t, schema)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	chromeTime := int64(13349793600000000)
	_, err = db.Exec(`INSERT INTO downloads (target_path, tab_url, total_bytes, start_time, state, mime_type) VALUES
		('/home/user/Downloads/file.zip', 'https://example.com/file.zip', 1048576, ?, 1, 'application/zip'),
		('/home/user/Downloads/doc.pdf', 'https://docs.example.com/report.pdf', 2048, ?, 0, 'application/pdf'),
		('/home/user/Downloads/cancelled.exe', 'https://example.com/app.exe', 0, ?, 2, 'application/octet-stream')`,
		chromeTime, chromeTime-1000000, chromeTime-2000000)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query("SELECT target_path, tab_url, total_bytes, start_time, state, mime_type FROM downloads ORDER BY start_time DESC LIMIT 500")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type dl struct {
		Path, URL, Mime string
		Size, StartTime int64
		State           int
	}
	var downloads []dl
	for rows.Next() {
		var d dl
		if err := rows.Scan(&d.Path, &d.URL, &d.Size, &d.StartTime, &d.State, &d.Mime); err != nil {
			t.Fatal(err)
		}
		downloads = append(downloads, d)
	}

	if len(downloads) != 3 {
		t.Fatalf("expected 3 downloads, got %d", len(downloads))
	}
	if downloads[0].State != 1 || chromeDownloadState(downloads[0].State) != "Complete" {
		t.Errorf("first download state = %d (%s)", downloads[0].State, chromeDownloadState(downloads[0].State))
	}
	if downloads[1].State != 0 || chromeDownloadState(downloads[1].State) != "In Progress" {
		t.Errorf("second download state = %d (%s)", downloads[1].State, chromeDownloadState(downloads[1].State))
	}
	if downloads[2].State != 2 || chromeDownloadState(downloads[2].State) != "Cancelled" {
		t.Errorf("third download state = %d (%s)", downloads[2].State, chromeDownloadState(downloads[2].State))
	}
}

// --- Firefox Downloads JSON Parsing Tests ---

func TestFirefoxDownloadsJSON_Parse(t *testing.T) {
	dlJSON := `{
		"schemaVersion": 1,
		"list": [
			{
				"source": "https://example.com/archive.tar.gz",
				"target": "file:///home/user/Downloads/archive.tar.gz",
				"startTime": 1705320000000,
				"totalBytes": 52428800,
				"state": 1,
				"contentType": "application/gzip"
			},
			{
				"source": "https://cdn.example.com/image.png",
				"target": "file:///home/user/Downloads/image.png",
				"startTime": 1705310000000,
				"totalBytes": 1024,
				"state": 2,
				"contentType": "image/png"
			},
			{
				"source": "https://example.com/huge-file.iso",
				"target": "file:///home/user/Downloads/huge-file.iso",
				"startTime": 1705300000000,
				"totalBytes": 4294967296,
				"state": 4,
				"contentType": "application/octet-stream"
			}
		]
	}`

	var parsed struct {
		List []struct {
			Source      string `json:"source"`
			Target      string `json:"target"`
			StartTime   int64  `json:"startTime"`
			TotalBytes  int64  `json:"totalBytes"`
			State       int    `json:"state"`
			ContentType string `json:"contentType"`
		} `json:"list"`
	}
	if err := json.Unmarshal([]byte(dlJSON), &parsed); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(parsed.List) != 3 {
		t.Fatalf("expected 3 downloads, got %d", len(parsed.List))
	}

	dl := parsed.List[0]
	if dl.Source != "https://example.com/archive.tar.gz" {
		t.Errorf("source = %q", dl.Source)
	}
	if dl.TotalBytes != 52428800 {
		t.Errorf("totalBytes = %d", dl.TotalBytes)
	}
	if firefoxDownloadState(dl.State) != "Complete" {
		t.Errorf("state = %q", firefoxDownloadState(dl.State))
	}

	// Verify file:// URI stripping (matching the code in browserDownloads)
	filePath := dl.Target
	if strings.HasPrefix(filePath, "file:///") {
		filePath = filePath[len("file://"):]
	}
	if filePath != "/home/user/Downloads/archive.tar.gz" {
		t.Errorf("file path = %q", filePath)
	}

	// Verify time conversion
	startTime := "unknown"
	if dl.StartTime > 0 {
		tt := time.Unix(dl.StartTime/1000, (dl.StartTime%1000)*1000000)
		startTime = tt.UTC().Format("2006-01-02 15:04:05")
	}
	if startTime != "2024-01-15 12:00:00" {
		t.Errorf("start time = %q", startTime)
	}

	// Verify large file size handling
	hugeDL := parsed.List[2]
	if hugeDL.TotalBytes != 4294967296 {
		t.Errorf("huge file size = %d", hugeDL.TotalBytes)
	}
	if firefoxDownloadState(hugeDL.State) != "Paused" {
		t.Errorf("huge file state = %q", firefoxDownloadState(hugeDL.State))
	}
}

func TestFirefoxDownloadsJSON_Empty(t *testing.T) {
	dlJSON := `{"schemaVersion": 1, "list": []}`
	var parsed struct {
		List []struct {
			Source string `json:"source"`
		} `json:"list"`
	}
	if err := json.Unmarshal([]byte(dlJSON), &parsed); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(parsed.List) != 0 {
		t.Errorf("expected 0, got %d", len(parsed.List))
	}
}

func TestFirefoxDownloadsJSON_MalformedEntry(t *testing.T) {
	dlJSON := `{
		"list": [
			{"source": "https://example.com/file.zip", "target": "", "startTime": 0, "totalBytes": -1, "state": 99}
		]
	}`
	var parsed struct {
		List []struct {
			Source     string `json:"source"`
			Target    string `json:"target"`
			StartTime int64  `json:"startTime"`
			TotalBytes int64  `json:"totalBytes"`
			State     int    `json:"state"`
		} `json:"list"`
	}
	if err := json.Unmarshal([]byte(dlJSON), &parsed); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	dl := parsed.List[0]
	if dl.Target != "" {
		t.Errorf("expected empty target, got %q", dl.Target)
	}
	if firefoxDownloadState(dl.State) != "Unknown(99)" {
		t.Errorf("state = %q", firefoxDownloadState(dl.State))
	}
	startTime := "unknown"
	if dl.StartTime > 0 {
		tt := time.Unix(dl.StartTime/1000, (dl.StartTime%1000)*1000000)
		startTime = tt.UTC().Format("2006-01-02 15:04:05")
	}
	if startTime != "unknown" {
		t.Errorf("expected 'unknown' for zero start time, got %q", startTime)
	}
}

// --- Output Formatting Tests ---

func TestHistoryOutputFormat(t *testing.T) {
	type historyEntry struct {
		Browser    string
		URL        string
		Title      string
		VisitCount int
		LastVisit  string
	}

	entries := []historyEntry{
		{"Chrome", "https://example.com/path?query=value", "Example Site", 5, "2024-01-15 12:00:00"},
		{"Firefox", "https://very-long-url.example.com/" + strings.Repeat("a", 200), "", 1, "2024-01-14 10:00:00"},
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Browser History (%d entries) ===\n\n", len(entries)))
	for _, e := range entries {
		title := e.Title
		if title == "" {
			title = "(no title)"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s\n  %s  (visits: %d, last: %s)\n",
			e.Browser, truncStr(title, 80), truncStr(e.URL, 120), e.VisitCount, e.LastVisit))
	}

	output := sb.String()
	if !strings.Contains(output, "=== Browser History (2 entries) ===") {
		t.Error("missing header")
	}
	if !strings.Contains(output, "[Chrome] Example Site") {
		t.Error("missing Chrome entry")
	}
	if !strings.Contains(output, "(no title)") {
		t.Error("missing empty title replacement")
	}
	if strings.Contains(output, strings.Repeat("a", 200)) {
		t.Error("URL should be truncated")
	}
	if !strings.Contains(output, "...") {
		t.Error("truncation marker missing")
	}
}

func TestDownloadsOutputFormat(t *testing.T) {
	type downloadEntry struct {
		Browser   string
		URL       string
		FilePath  string
		Size      int64
		State     string
		MimeType  string
		StartTime string
	}

	entries := []downloadEntry{
		{"Chrome", "https://example.com/file.zip", "/home/user/Downloads/file.zip", 1048576, "Complete", "application/zip", "2024-01-15 12:00:00"},
		{"Firefox", "https://example.com/doc.pdf", "/home/user/Downloads/doc.pdf", 0, "Failed", "application/pdf", "2024-01-14 10:00:00"},
		{"Chrome (Profile 1)", "https://example.com/big.iso", "/home/user/Downloads/big.iso", -1, "In Progress", "", "unknown"},
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Browser Downloads (%d entries) ===\n\n", len(entries)))
	for _, e := range entries {
		sizeStr := "unknown"
		if e.Size >= 0 {
			sizeStr = formatBytes(uint64(e.Size))
		}
		sb.WriteString(fmt.Sprintf("[%s] %s (%s, %s)\n  URL: %s\n  File: %s\n",
			e.Browser, e.State, sizeStr, e.StartTime,
			truncStr(e.URL, 120), truncStr(e.FilePath, 120)))
		if e.MimeType != "" {
			sb.WriteString(fmt.Sprintf("  Type: %s\n", e.MimeType))
		}
		sb.WriteString("\n")
	}

	output := sb.String()
	if !strings.Contains(output, "=== Browser Downloads (3 entries) ===") {
		t.Error("missing header")
	}
	if !strings.Contains(output, "Complete (1.0 MB") {
		t.Error("missing formatted size")
	}
	if !strings.Contains(output, "Failed (0 B") {
		t.Error("missing zero byte format")
	}
	if !strings.Contains(output, "In Progress (unknown") {
		t.Error("missing negative size as unknown")
	}
	if !strings.Contains(output, "Type: application/zip") {
		t.Error("missing mime type")
	}
	if strings.Count(output, "Type:") != 2 {
		t.Error("empty mime type should not produce Type: line")
	}
}

func TestAutofillOutputFormat(t *testing.T) {
	type autofillEntry struct {
		Browser      string
		FieldName    string
		Value        string
		Count        int
		DateLastUsed string
	}

	entries := []autofillEntry{
		{"Chrome", "email", "user@example.com", 15, "2024-01-15 12:00:00"},
		{"Chrome (Profile 1)", "address", strings.Repeat("x", 100), 1, "2024-01-10 08:00:00"},
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Browser Autofill (%d entries) ===\n\n", len(entries)))
	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("[%s] %s = %s  (used: %d times, last: %s)\n",
			e.Browser, e.FieldName, truncStr(e.Value, 60), e.Count, e.DateLastUsed))
	}

	output := sb.String()
	if !strings.Contains(output, "email = user@example.com") {
		t.Error("missing email entry")
	}
	if !strings.Contains(output, "(used: 15 times") {
		t.Error("missing use count")
	}
	if strings.Contains(output, strings.Repeat("x", 100)) {
		t.Error("long value should be truncated")
	}
}

func TestCookiesOutputFormat(t *testing.T) {
	type cookie struct {
		Browser, Host, Name, Value, Path string
		Secure, HTTPOnly                 bool
	}

	cookies := []cookie{
		{"Chrome", ".example.com", "session", "abc123", "/", true, true},
		{"Firefox", ".github.com", "_gh", "token", "/api", false, true},
		{"Edge", "plain.com", "pref", "dark", "/", false, false},
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Browser Cookies (%d found) ===\n\n", len(cookies)))
	for _, c := range cookies {
		flags := ""
		if c.Secure {
			flags += " Secure"
		}
		if c.HTTPOnly {
			flags += " HttpOnly"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s  %s=%s  (path=%s%s)\n",
			c.Browser, c.Host, c.Name, truncStr(c.Value, 80), c.Path, flags))
	}

	output := sb.String()
	if !strings.Contains(output, "Secure HttpOnly") {
		t.Error("missing secure+httponly flags")
	}
	if !strings.Contains(output, "(path=/api HttpOnly)") {
		t.Error("missing httponly-only flag")
	}
	if strings.Contains(output, "plain.com  pref=dark  (path=/ Secure") {
		t.Error("non-secure cookie should not have Secure flag")
	}
}

// --- Firefox Cookie Expiry Handling ---

func TestFirefoxCookieExpiryConversion(t *testing.T) {
	// Firefox cookies.sqlite stores expiry in seconds, but the code multiplies by 1000000
	// to convert to PRTime (microseconds) for firefoxTimeToString
	expiry := int64(1705320000) // 2024-01-15 12:00:00 UTC in seconds
	prtime := expiry * 1000000
	result := firefoxTimeToString(prtime)
	if result != "2024-01-15 12:00:00" {
		t.Errorf("expiry conversion = %q, want '2024-01-15 12:00:00'", result)
	}
}

// --- Profile Label Formatting ---

func TestProfileLabelFormatting(t *testing.T) {
	tests := []struct {
		browser, profile, want string
	}{
		{"Chrome", "Default", "Chrome"},
		{"Chrome", "Profile 1", "Chrome (Profile 1)"},
		{"Edge", "Default", "Edge"},
		{"Firefox", "a1b2c3d4.default-release", "Firefox (a1b2c3d4.default-release)"},
	}

	for _, tt := range tests {
		label := tt.browser
		if tt.profile != "Default" {
			label = fmt.Sprintf("%s (%s)", tt.browser, tt.profile)
		}
		if label != tt.want {
			t.Errorf("label(%q, %q) = %q, want %q", tt.browser, tt.profile, label, tt.want)
		}
	}
}

// --- Special Character Handling ---

func TestSpecialCharactersInBrowserData(t *testing.T) {
	schema := `CREATE TABLE urls (
		id INTEGER PRIMARY KEY,
		url TEXT,
		title TEXT,
		visit_count INTEGER,
		last_visit_time INTEGER
	)`
	dbPath := createTempDB(t, schema)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES
		('https://example.com/search?q=hello+world&lang=en', 'Search: "hello world"', 1, 1705320000),
		('https://example.com/path with spaces', 'Title with <html> & "quotes"', 2, 1705310000),
		('https://example.com/unicode/日本語', '日本語のページ', 3, 1705300000),
		('https://example.com/emoji/🔒', 'Lock 🔒 Page', 1, 1705290000)`)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		var url, title string
		var visits int
		var lastVisit int64
		if err := rows.Scan(&url, &title, &visits, &lastVisit); err != nil {
			t.Fatal(err)
		}
		count++
	}

	if count != 4 {
		t.Errorf("expected 4 entries with special chars, got %d", count)
	}
}

// --- Format Helpers Additional Coverage ---

func TestTruncStr_BrowserEdgeCases(t *testing.T) {
	if truncStr("", 10) != "" {
		t.Error("empty string should stay empty")
	}
	long := strings.Repeat("x", 200)
	result := truncStr(long, 120)
	if len(result) > 120 {
		t.Errorf("truncated string length = %d, want <= 120", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Error("truncated string should end with ...")
	}
}

func TestFormatBytes_BrowserDownloadSizes(t *testing.T) {
	if formatBytes(0) != "0 B" {
		t.Errorf("0 bytes = %q", formatBytes(0))
	}
	if formatBytes(1048576) != "1.0 MB" {
		t.Errorf("1MB = %q", formatBytes(1048576))
	}
	if formatBytes(1099511627776) != "1.0 TB" {
		t.Errorf("1TB = %q", formatBytes(1099511627776))
	}
}

// --- Browser Bookmarks JSON Edge Cases ---

func TestBookmarkJSON_SyncTransactionVersion(t *testing.T) {
	// Chrome includes "sync_transaction_version" as a string in roots — should be skipped
	bookmarkJSON := `{
		"roots": {
			"bookmark_bar": {
				"type": "folder",
				"name": "Bookmarks bar",
				"children": [
					{"type": "url", "name": "Test", "url": "https://test.com"}
				]
			},
			"sync_transaction_version": "1",
			"other": {
				"type": "folder",
				"name": "Other bookmarks",
				"children": []
			}
		}
	}`

	var bmFile struct {
		Roots map[string]json.RawMessage `json:"roots"`
	}
	if err := json.Unmarshal([]byte(bookmarkJSON), &bmFile); err != nil {
		t.Fatal(err)
	}

	var allBookmarks []browserBookmarkEntry
	for rootName, raw := range bmFile.Roots {
		if len(raw) == 0 || raw[0] != '{' {
			continue
		}
		var node bookmarkNode
		if err := json.Unmarshal(raw, &node); err != nil {
			continue
		}
		extractBookmarks(&node, "Chrome", rootName, &allBookmarks)
	}

	if len(allBookmarks) != 1 {
		t.Fatalf("expected 1 bookmark (sync_transaction_version skipped), got %d", len(allBookmarks))
	}
	if allBookmarks[0].Name != "Test" {
		t.Errorf("bookmark name = %q", allBookmarks[0].Name)
	}
}

func TestBookmarkJSON_DeeplyNested(t *testing.T) {
	bookmarkJSON := `{
		"roots": {
			"bookmark_bar": {
				"type": "folder",
				"name": "Bar",
				"children": [{
					"type": "folder",
					"name": "Level1",
					"children": [{
						"type": "folder",
						"name": "Level2",
						"children": [{
							"type": "url",
							"name": "Deep Link",
							"url": "https://deep.example.com"
						}]
					}]
				}]
			}
		}
	}`

	var bmFile struct {
		Roots map[string]json.RawMessage `json:"roots"`
	}
	json.Unmarshal([]byte(bookmarkJSON), &bmFile)

	var allBookmarks []browserBookmarkEntry
	for rootName, raw := range bmFile.Roots {
		if len(raw) == 0 || raw[0] != '{' {
			continue
		}
		var node bookmarkNode
		json.Unmarshal(raw, &node)
		extractBookmarks(&node, "Chrome", rootName, &allBookmarks)
	}

	if len(allBookmarks) != 1 {
		t.Fatalf("expected 1 deep bookmark, got %d", len(allBookmarks))
	}
	if allBookmarks[0].Folder != "bookmark_bar/Level1/Level2" {
		t.Errorf("folder = %q, want 'bookmark_bar/Level1/Level2'", allBookmarks[0].Folder)
	}
}
