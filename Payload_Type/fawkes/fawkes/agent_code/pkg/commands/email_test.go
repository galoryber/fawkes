//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestEmailCommandName(t *testing.T) {
	assertCommandName(t, &EmailCommand{}, "email")
}

func TestEmailCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &EmailCommand{})
}

func TestEmailEmptyParamsDefaultsCount(t *testing.T) {
	cmd := &EmailCommand{}
	// Empty params should default to "count" action
	result := cmd.Execute(mockTask("email", ""))
	// Will try COM — error in test env is expected but not panic
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %q", result.Status)
	}
}

func TestEmailInvalidJSON(t *testing.T) {
	cmd := &EmailCommand{}
	result := cmd.Execute(mockTask("email", "not json"))
	assertError(t, result)
}

func TestEmailUnknownAction(t *testing.T) {
	cmd := &EmailCommand{}
	params, _ := json.Marshal(emailArgs{Action: "badaction"})
	result := cmd.Execute(mockTask("email", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestEmailSearchMissingQuery(t *testing.T) {
	cmd := &EmailCommand{}
	params, _ := json.Marshal(emailArgs{Action: "search"})
	result := cmd.Execute(mockTask("email", string(params)))
	assertError(t, result)
}

func TestEmailReadMissingIndex(t *testing.T) {
	cmd := &EmailCommand{}
	params, _ := json.Marshal(emailArgs{Action: "read"})
	result := cmd.Execute(mockTask("email", string(params)))
	assertError(t, result)
}

func TestEmailReadZeroIndex(t *testing.T) {
	cmd := &EmailCommand{}
	params, _ := json.Marshal(emailArgs{Action: "read", Index: 0})
	result := cmd.Execute(mockTask("email", string(params)))
	assertError(t, result)
}

func TestEmailArgsUnmarshal(t *testing.T) {
	var args emailArgs
	data := `{"action":"search","folder":"Sent Items","query":"password","count":5,"headers":true}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Action != "search" {
		t.Errorf("expected action=search, got %q", args.Action)
	}
	if args.Folder != "Sent Items" {
		t.Errorf("expected folder=Sent Items, got %q", args.Folder)
	}
	if args.Count != 5 {
		t.Errorf("expected count=5, got %d", args.Count)
	}
	if !args.Headers {
		t.Error("expected headers=true")
	}
}

func TestEmailFolderConstants(t *testing.T) {
	// Verify Outlook OLE folder ID constants
	if olFolderInbox != 6 {
		t.Errorf("olFolderInbox = %d, want 6", olFolderInbox)
	}
	if olFolderSentMail != 5 {
		t.Errorf("olFolderSentMail = %d, want 5", olFolderSentMail)
	}
	if olFolderDrafts != 16 {
		t.Errorf("olFolderDrafts = %d, want 16", olFolderDrafts)
	}
	if olFolderDeletedItems != 3 {
		t.Errorf("olFolderDeletedItems = %d, want 3", olFolderDeletedItems)
	}
	if olFolderJunk != 23 {
		t.Errorf("olFolderJunk = %d, want 23", olFolderJunk)
	}
}
