package agentfunctions

import (
	"strings"
	"testing"
)

func TestClassifyTicketType_GoldenTicket(t *testing.T) {
	result := classifyTicketType("forge", "")
	if result != "Golden Ticket (TGT)" {
		t.Errorf("expected Golden Ticket, got %s", result)
	}
}

func TestClassifyTicketType_SilverTicket(t *testing.T) {
	result := classifyTicketType("forge", "cifs/fileserver.corp.local")
	if result != "Silver Ticket (TGS)" {
		t.Errorf("expected Silver Ticket, got %s", result)
	}
}

func TestClassifyTicketType_Request(t *testing.T) {
	result := classifyTicketType("request", "")
	if !strings.Contains(result, "Overpass") {
		t.Errorf("expected Overpass-the-Hash, got %s", result)
	}
}

func TestClassifyTicketType_Diamond(t *testing.T) {
	result := classifyTicketType("diamond", "")
	if result != "Diamond Ticket" {
		t.Errorf("expected Diamond Ticket, got %s", result)
	}
}

func TestClassifyTicketType_Renew(t *testing.T) {
	result := classifyTicketType("renew", "")
	if result != "TGT Renewal" {
		t.Errorf("expected TGT Renewal, got %s", result)
	}
}

func TestClassifyTicketType_S4U(t *testing.T) {
	result := classifyTicketType("s4u", "cifs/server")
	if result != "S4U Delegation" {
		t.Errorf("expected S4U Delegation, got %s", result)
	}
}

func TestClassifyTicketType_Unknown(t *testing.T) {
	result := classifyTicketType("unknown", "")
	if result != "Kerberos Ticket" {
		t.Errorf("expected Kerberos Ticket, got %s", result)
	}
}

func TestTicketForgeDisplayParams_GoldenTicket(t *testing.T) {
	result := ticketForgeDisplayParams("forge", "Administrator", "CORP.LOCAL", "")
	if !strings.Contains(result, "Golden Ticket") || !strings.Contains(result, "Administrator@CORP.LOCAL") {
		t.Errorf("unexpected display: %s", result)
	}
}

func TestTicketForgeDisplayParams_SilverTicket(t *testing.T) {
	result := ticketForgeDisplayParams("forge", "admin", "CORP.LOCAL", "cifs/server")
	if !strings.Contains(result, "Silver Ticket") || !strings.Contains(result, "admin@CORP.LOCAL") {
		t.Errorf("unexpected display: %s", result)
	}
}

func TestTicketForgeDisplayParams_S4U(t *testing.T) {
	result := ticketForgeDisplayParams("s4u", "sqlsvc", "CORP.LOCAL", "cifs/fileserver")
	if !strings.Contains(result, "S4U") || !strings.Contains(result, "sqlsvc@CORP.LOCAL") || !strings.Contains(result, "cifs/fileserver") {
		t.Errorf("unexpected display: %s", result)
	}
}

func TestTicketForgeDisplayParams_Request(t *testing.T) {
	result := ticketForgeDisplayParams("request", "user", "DOMAIN.COM", "")
	if !strings.Contains(result, "Overpass") || !strings.Contains(result, "user@DOMAIN.COM") {
		t.Errorf("unexpected display: %s", result)
	}
}
