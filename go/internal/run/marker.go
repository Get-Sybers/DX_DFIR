package run

import (
	"regexp"
	"strings"
)

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
