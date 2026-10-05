package run

import (
	"regexp"
	"strings"
)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// Sanitize prepares a raw output line for display: it drops everything before
// the last carriage return (collapsing in-place progress-bar redraws to their
// final state) and strips ANSI escape sequences, so a tailed log line is safe
// to print verbatim.
func Sanitize(line string) string {
	if i := strings.LastIndexByte(line, '\r'); i >= 0 {
		line = line[i+1:]
	}
	line = ansiRE.ReplaceAllString(line, "")
	return strings.TrimRight(line, " \t")
}
