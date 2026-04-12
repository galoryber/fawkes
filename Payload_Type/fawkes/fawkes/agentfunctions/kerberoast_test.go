package agentfunctions

import (
	"testing"
)

func TestParseKerberoastEntries_ValidJSON(t *testing.T) {
	input := `[{"account":"sqlsvc","spn":"MSSQL/db01.corp.local","etype":"23","hash":"$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQL/db01*$abc...","status":"roasted"},{"account":"websvc","spn":"HTTP/web01","etype":"17","hash":"","status":"no_tgs"}]`
	entries, err := parseKerberoastEntries(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Account != "sqlsvc" {
		t.Errorf("expected account sqlsvc, got %s", entries[0].Account)
	}
	if entries[0].Status != "roasted" {
		t.Errorf("expected status roasted, got %s", entries[0].Status)
	}
}

func TestParseKerberoastEntries_EmptyArray(t *testing.T) {
	entries, err := parseKerberoastEntries("[]")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseKerberoastEntries_InvalidJSON(t *testing.T) {
	_, err := parseKerberoastEntries("not json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestFilterRoastedEntries(t *testing.T) {
	entries := []kerberoastEntry{
		{Account: "sqlsvc", Hash: "$krb5tgs$...", Status: "roasted"},
		{Account: "websvc", Hash: "", Status: "no_tgs"},
		{Account: "httpsvc", Hash: "$krb5tgs$...", Status: "roasted"},
		{Account: "nosvc", Hash: "$krb5tgs$...", Status: "error"},
	}
	roasted := filterRoastedEntries(entries)
	if len(roasted) != 2 {
		t.Fatalf("expected 2 roasted entries, got %d", len(roasted))
	}
	if roasted[0].Account != "sqlsvc" {
		t.Errorf("expected sqlsvc, got %s", roasted[0].Account)
	}
	if roasted[1].Account != "httpsvc" {
		t.Errorf("expected httpsvc, got %s", roasted[1].Account)
	}
}

func TestFilterRoastedEntries_EmptyHash(t *testing.T) {
	entries := []kerberoastEntry{
		{Account: "sqlsvc", Hash: "", Status: "roasted"},
	}
	roasted := filterRoastedEntries(entries)
	if len(roasted) != 0 {
		t.Errorf("expected 0 entries for empty hash, got %d", len(roasted))
	}
}

func TestFilterRoastedEntries_NilInput(t *testing.T) {
	roasted := filterRoastedEntries(nil)
	if len(roasted) != 0 {
		t.Errorf("expected 0 entries for nil input, got %d", len(roasted))
	}
}

func TestCountRoastedInText(t *testing.T) {
	text := `[{"status":"roasted","hash":"abc"},{"status":"no_tgs"},{"status":"roasted","hash":"def"}]`
	count := countRoastedInText(text)
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}
}

func TestCountRoastedInText_None(t *testing.T) {
	count := countRoastedInText(`[{"status":"no_tgs"}]`)
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}
