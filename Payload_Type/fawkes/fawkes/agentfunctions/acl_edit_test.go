package agentfunctions

import (
	"testing"
)

func TestFindDangerousACEs_GenericAll(t *testing.T) {
	input := "ACE: CORP\\Domain Admins - GenericAll - Allow"
	found := findDangerousACEs(input)
	if len(found) != 1 {
		t.Fatalf("expected 1 dangerous ACE, got %d", len(found))
	}
}

func TestFindDangerousACEs_Multiple(t *testing.T) {
	input := `ACE: CORP\jsmith - ReadProperty - Allow
ACE: CORP\jsmith - WriteDACL - Allow
ACE: CORP\backup_svc - GenericWrite - Allow
ACE: Everyone - ReadProperty - Allow`

	found := findDangerousACEs(input)
	if len(found) != 2 {
		t.Fatalf("expected 2 dangerous ACEs, got %d", len(found))
	}
}

func TestFindDangerousACEs_DCSync(t *testing.T) {
	input := "ACE: CORP\\attacker - DS-Replication-Get-Changes - Allow"
	found := findDangerousACEs(input)
	if len(found) != 1 {
		t.Fatalf("expected 1 (DCSync right), got %d", len(found))
	}
}

func TestFindDangerousACEs_None(t *testing.T) {
	input := `ACE: Everyone - ReadProperty - Allow
ACE: CORP\Users - ListChildren - Allow`

	found := findDangerousACEs(input)
	if len(found) != 0 {
		t.Errorf("expected 0 dangerous ACEs, got %d", len(found))
	}
}

func TestFindDangerousACEs_AllDangerous(t *testing.T) {
	input := `GenericAll found
WriteDACL present
WriteOwner here
GenericWrite too
DS-Replication-Get-Changes exploitable
ForceChangePassword possible
AllExtendedRights granted`

	found := findDangerousACEs(input)
	if len(found) != 7 {
		t.Errorf("expected 7 dangerous ACEs, got %d", len(found))
	}
}

func TestFindDangerousACEs_Empty(t *testing.T) {
	found := findDangerousACEs("")
	if len(found) != 0 {
		t.Errorf("expected 0, got %d", len(found))
	}
}
