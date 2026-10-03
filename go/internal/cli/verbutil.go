package cli

// Small filesystem + interaction helpers shared by the mechanical verbs
// (validate, build-*, car, stack, cleanup, list). Kept UI-agnostic: prompts go
// to stderr so a verb's stdout stays pipe-clean for machine-readable payloads.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// fileExists reports whether p is an existing regular (non-directory) file.
func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// dirExists reports whether p is an existing directory.
func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// confirmYes prints prompt to stderr (so stdout stays clean) and reads one line
// from stdin, returning true only for an affirmative answer. The caller is
// responsible for the "[y/N]" hint, matching the wording of the retired Python
// CLI's confirmation prompts.
func confirmYes(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
