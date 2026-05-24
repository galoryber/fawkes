package agentfunctions

import (
	"testing"
)

func TestParseComputerNames_Standard(t *testing.T) {
	input := `=== Computers ===
- 5 results
DC01$           dc01.corp.local
DC02$           dc02.corp.local
SRV01$          srv01.corp.local`
	computers := parseComputerNames(input)
	if len(computers) != 3 {
		t.Fatalf("expected 3 computers, got %d", len(computers))
	}
	if computers[0] != "DC01$" {
		t.Errorf("expected DC01$, got %s", computers[0])
	}
}

func TestParseComputerNames_NoComputers(t *testing.T) {
	input := `=== Users ===
- 5 results
admin           Administrator
user1           John Doe`
	computers := parseComputerNames(input)
	if len(computers) != 0 {
		t.Errorf("expected 0 computers, got %d", len(computers))
	}
}

func TestParseComputerNames_EmptyInput(t *testing.T) {
	computers := parseComputerNames("")
	if len(computers) != 0 {
		t.Errorf("expected 0, got %d", len(computers))
	}
}

func TestParseComputerNames_SkipsHeaders(t *testing.T) {
	input := `=== Computers ($) ===
- count: 2
DC01$           dc01.corp.local`
	computers := parseComputerNames(input)
	// "===" line contains $ but starts with "=", should be skipped
	// "- count" starts with "-", should be skipped
	if len(computers) != 1 {
		t.Fatalf("expected 1 computer, got %d: %v", len(computers), computers)
	}
}

func TestParseTrustDomains_Standard(t *testing.T) {
	input := `=== Domain Trusts ===
- 3 trusts found
Trust Direction: Bidirectional
north.sevenkingdoms.local     child        bidirectional
essos.local                   forest       bidirectional`
	domains := parseTrustDomains(input)
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d: %v", len(domains), domains)
	}
	if domains[0] != "north.sevenkingdoms.local" {
		t.Errorf("expected north.sevenkingdoms.local, got %s", domains[0])
	}
	if domains[1] != "essos.local" {
		t.Errorf("expected essos.local, got %s", domains[1])
	}
}

func TestParseTrustDomains_NoDomains(t *testing.T) {
	input := `=== Users ===
admin
user1`
	domains := parseTrustDomains(input)
	if len(domains) != 0 {
		t.Errorf("expected 0 domains, got %d", len(domains))
	}
}

func TestParseTrustDomains_SkipsTrustPrefix(t *testing.T) {
	input := `Trust: bidirectional
child.domain.local   child`
	domains := parseTrustDomains(input)
	// "Trust: bidirectional" starts with "Trust", should be skipped
	if len(domains) != 1 {
		t.Fatalf("expected 1 domain, got %d: %v", len(domains), domains)
	}
	if domains[0] != "child.domain.local" {
		t.Errorf("expected child.domain.local, got %s", domains[0])
	}
}

func TestParseTrustDomains_EmptyInput(t *testing.T) {
	domains := parseTrustDomains("")
	if len(domains) != 0 {
		t.Errorf("expected 0, got %d", len(domains))
	}
}
