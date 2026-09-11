package run

import (
	"encoding/json"
	"regexp"
	"strings"
)

// SentinelPrefix marks a machine-readable progress line the Python helpers emit
// on stderr, e.g.  ::dxdfir:: {"phase":"hash","done_bytes":123,...}
// Everything else on the stream is treated as human log text.
const SentinelPrefix = "::dxdfir::"

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// Sanitize prepares a raw output line for display in a termui widget: it drops
// everything before the last carriage return (collapsing in-place progress-bar
// redraws to their final state), strips ANSI escape sequences, and defuses
// termui's [text](style) markup by breaking the "](" adjacency its parser needs
// — so literal brackets in forensic paths/timestamps render verbatim.
func Sanitize(line string) string {
	if i := strings.LastIndexByte(line, '\r'); i >= 0 {
		line = line[i+1:]
	}
	line = ansiRE.ReplaceAllString(line, "")
	line = strings.ReplaceAll(line, "](", "] (")
	return strings.TrimRight(line, " \t")
}

// Sentinel is a decoded progress line. Fields are optional; a consumer reads the
// ones relevant to the phase it drives. The schema is shared with the Python
// helpers (get_sybers_dxdfir.collection --progress).
type Sentinel struct {
	Phase      string `json:"phase"`       // "classify" | "move" | "hash" | "summary" | "note"
	File       string `json:"file"`        // current file basename
	Lane       string `json:"lane"`        // destination lane / bucket
	How        string `json:"how"`         // classify decision: magic|ext|ambiguous:..|unknown
	Action     string `json:"action"`      // moved|skip
	Reason     string `json:"reason"`      // skip reason
	Done       int    `json:"done"`        // items completed
	Total      int    `json:"total"`       // items total
	DoneBytes  int64  `json:"done_bytes"`  // bytes hashed so far
	TotalBytes int64  `json:"total_bytes"` // bytes to hash
	FileDone   int    `json:"file_done"`   // file index (hash phase)
	FileTotal  int    `json:"file_total"`  // file count (hash phase)
	Text       string `json:"text"`        // free-form note / summary text
}

// ParseSentinel returns the decoded sentinel if line is one, else ok=false.
func ParseSentinel(line string) (Sentinel, bool) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, SentinelPrefix) {
		return Sentinel{}, false
	}
	payload := strings.TrimSpace(strings.TrimPrefix(s, SentinelPrefix))
	var out Sentinel
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return Sentinel{}, false
	}
	return out, true
}
