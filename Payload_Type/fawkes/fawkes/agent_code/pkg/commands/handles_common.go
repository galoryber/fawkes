package commands

import (
	"encoding/json"
	"sort"

	"fawkes/pkg/structs"
)

// handlesArgs contains parameters shared across all platforms.
type handlesArgs struct {
	PID       int    `json:"pid"`
	TypeName  string `json:"type"`
	MaxCount  int    `json:"max_count"`
	ShowNames bool   `json:"show_names"`
}

// handleInfo represents a single open handle/file descriptor.
type handleInfo struct {
	Handle   int    `json:"handle"`
	TypeName string `json:"type"`
	Name     string `json:"name,omitempty"`
}

type handleTypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// formatHandleResult formats handle enumeration results as JSON.
func formatHandleResult(handles []handleInfo, typeCounts map[string]int, args handlesArgs, total int) structs.CommandResult {
	var summary []handleTypeCount
	for name, count := range typeCounts {
		summary = append(summary, handleTypeCount{name, count})
	}
	sort.Slice(summary, func(i, j int) bool { return summary[i].Count > summary[j].Count })

	type handlesOutput struct {
		PID     int               `json:"pid"`
		Shown   int               `json:"shown"`
		Total   int               `json:"total"`
		Summary []handleTypeCount `json:"summary"`
		Handles []handleInfo      `json:"handles"`
	}

	out := handlesOutput{
		PID:     args.PID,
		Shown:   len(handles),
		Total:   total,
		Summary: summary,
		Handles: handles,
	}

	jsonBytes, err := json.Marshal(out)
	if err != nil {
		return errorf("Error marshalling handle data: %v", err)
	}

	return successResult(string(jsonBytes))
}
