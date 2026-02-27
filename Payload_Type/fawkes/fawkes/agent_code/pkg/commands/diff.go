package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// DiffCommand implements file comparison
type DiffCommand struct{}

func (c *DiffCommand) Name() string {
	return "diff"
}

func (c *DiffCommand) Description() string {
	return "Compare two files and show differences"
}

type diffArgs struct {
	File1   string `json:"file1"`
	File2   string `json:"file2"`
	Context int    `json:"context"` // context lines around changes (default 3)
}

func (c *DiffCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: no parameters provided",
			Status:    "error",
			Completed: true,
		}
	}

	var args diffArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.File1 == "" || args.File2 == "" {
		return structs.CommandResult{
			Output:    "Error: both file1 and file2 are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Context == 0 {
		args.Context = 3
	}

	lines1, err := readLines(args.File1)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading %s: %v", args.File1, err),
			Status:    "error",
			Completed: true,
		}
	}

	lines2, err := readLines(args.File2)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading %s: %v", args.File2, err),
			Status:    "error",
			Completed: true,
		}
	}

	hunks := diffLines(lines1, lines2, args.Context)

	if len(hunks) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("[*] Files are identical (%d lines)", len(lines1)),
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- %s (%d lines)\n", args.File1, len(lines1)))
	sb.WriteString(fmt.Sprintf("+++ %s (%d lines)\n", args.File2, len(lines2)))

	for _, hunk := range hunks {
		sb.WriteString(hunk)
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// diffLines produces unified diff hunks using a simple LCS-based diff
func diffLines(a, b []string, context int) []string {
	// Build edit script using Myers-like approach (simple O(NM) LCS)
	m, n := len(a), len(b)

	// For very large files, limit diff to first 10000 lines each
	maxLines := 10000
	if m > maxLines {
		a = a[:maxLines]
		m = maxLines
	}
	if n > maxLines {
		b = b[:maxLines]
		n = maxLines
	}

	// Build LCS table
	lcs := make([][]int, m+1)
	for i := range lcs {
		lcs[i] = make([]int, n+1)
	}
	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	// Generate edit operations
	type edit struct {
		op   byte // '=', '-', '+'
		lineA int
		lineB int
		text string
	}

	var edits []edit
	i, j := 0, 0
	for i < m && j < n {
		if a[i] == b[j] {
			edits = append(edits, edit{'=', i, j, a[i]})
			i++
			j++
		} else if lcs[i+1][j] >= lcs[i][j+1] {
			edits = append(edits, edit{'-', i, j, a[i]})
			i++
		} else {
			edits = append(edits, edit{'+', i, j, b[j]})
			j++
		}
	}
	for i < m {
		edits = append(edits, edit{'-', i, j, a[i]})
		i++
	}
	for j < n {
		edits = append(edits, edit{'+', i, j, b[j]})
		j++
	}

	// Group edits into hunks with context
	var hunks []string
	var hunkEdits []edit
	lastChange := -1

	flushHunk := func() {
		if len(hunkEdits) == 0 {
			return
		}
		// Calculate hunk header
		startA, startB := -1, -1
		countA, countB := 0, 0
		for _, e := range hunkEdits {
			switch e.op {
			case '=':
				if startA == -1 {
					startA = e.lineA
					startB = e.lineB
				}
				countA++
				countB++
			case '-':
				if startA == -1 {
					startA = e.lineA
					startB = e.lineB
				}
				countA++
			case '+':
				if startA == -1 {
					startA = e.lineA
					startB = e.lineB
				}
				countB++
			}
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", startA+1, countA, startB+1, countB))
		for _, e := range hunkEdits {
			switch e.op {
			case '=':
				sb.WriteString(fmt.Sprintf(" %s\n", e.text))
			case '-':
				sb.WriteString(fmt.Sprintf("-%s\n", e.text))
			case '+':
				sb.WriteString(fmt.Sprintf("+%s\n", e.text))
			}
		}
		hunks = append(hunks, sb.String())
		hunkEdits = nil
	}

	for idx, e := range edits {
		if e.op != '=' {
			if lastChange == -1 || idx-lastChange > 2*context {
				flushHunk()
				// Add leading context
				start := idx - context
				if start < 0 {
					start = 0
				}
				for ci := start; ci < idx; ci++ {
					if edits[ci].op == '=' {
						hunkEdits = append(hunkEdits, edits[ci])
					}
				}
			}
			lastChange = idx
			hunkEdits = append(hunkEdits, e)
		} else if lastChange >= 0 && idx-lastChange <= context {
			hunkEdits = append(hunkEdits, e)
		} else if lastChange >= 0 && idx-lastChange <= 2*context {
			hunkEdits = append(hunkEdits, e)
		}
	}
	flushHunk()

	return hunks
}
