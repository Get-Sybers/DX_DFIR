package lanes

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// glob joins parts into a pattern under root and returns matches (nil on error).
func glob(root string, parts ...string) []string {
	pattern := filepath.Join(append([]string{root}, parts...)...)
	m, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return m
}

// uniqueParents returns the distinct parent directories of the given paths.
func uniqueParents(paths []string) []string {
	seen := map[string]struct{}{}
	for _, p := range paths {
		seen[filepath.Dir(p)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	return out
}

// hostDirsWithOutput returns the immediate subdirectories of outDir that contain
// at least one non-empty regular file (a completed zimmerman host).
func hostDirsWithOutput(outDir string) []string {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(outDir, e.Name())
		if dirHasNonEmptyFile(dir) {
			out = append(out, dir)
		}
	}
	return out
}

func dirHasNonEmptyFile(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil && fi.Size() > 0 {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func fileNonEmpty(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

// biggestMatch returns the size (bytes) of the largest file matching the glob —
// used as plaso's "still alive" heartbeat (the growing .plaso db).
func biggestMatch(root string, parts ...string) int64 {
	var max int64
	for _, m := range glob(root, parts...) {
		if fi, err := os.Stat(m); err == nil && fi.Size() > max {
			max = fi.Size()
		}
	}
	return max
}

// newestMatch returns the most recently modified file matching the glob, or "".
func newestMatch(root string, parts ...string) string {
	var newest string
	var newestMod int64 = -1
	for _, m := range glob(root, parts...) {
		if fi, err := os.Stat(m); err == nil && fi.ModTime().UnixNano() > newestMod {
			newestMod = fi.ModTime().UnixNano()
			newest = m
		}
	}
	return newest
}

// readTail returns up to n filtered trailing lines of a (possibly large) log
// file: it reads only the last maxBytes, strips redraw noise, collapses runs of
// duplicate lines to "line (xN)", and keeps only lines likely to carry signal.
func readTail(path string, n, maxBytes int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	if fi.Size() > int64(maxBytes) {
		_, _ = f.Seek(-int64(maxBytes), 2) // from end
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var lines []string
	for sc.Scan() {
		t := sanitizeLog(sc.Text())
		if t == "" || !keepLine(t) {
			continue
		}
		lines = append(lines, t)
	}
	lines = collapseDuplicates(lines)
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// keepLine filters a tool log to the lines an operator actually needs on a long
// run — names of plugins/parsers, percentages, errors/warnings — and drops the
// banner/redraw noise that would recreate the firehose.
func keepLine(s string) bool {
	l := strings.ToLower(s)
	for _, kw := range []string{
		"error", "fail", "warn", "traceback", "exception",
		"plugin", "parser", "%", "scan", "extract", "process", "complete",
		"symbol", "no ", "skip",
	} {
		if strings.Contains(l, kw) {
			return true
		}
	}
	return false
}

func collapseDuplicates(in []string) []string {
	var out []string
	for _, s := range in {
		if len(out) > 0 && base(out[len(out)-1]) == s {
			// bump the count on the previous line
			out[len(out)-1] = incCount(out[len(out)-1])
			continue
		}
		out = append(out, s)
	}
	return out
}

func base(s string) string {
	if i := strings.LastIndex(s, "  (x"); i >= 0 && strings.HasSuffix(s, ")") {
		return s[:i]
	}
	return s
}

func incCount(s string) string {
	b := base(s)
	if b == s {
		return s + "  (x2)"
	}
	// parse existing count
	rest := strings.TrimSuffix(strings.TrimPrefix(s[len(b):], "  (x"), ")")
	n := 2
	if v, err := atoi(rest); err == nil {
		n = v + 1
	}
	return b + "  (x" + itoa(n) + ")"
}

// small strconv-free helpers to keep the hot path allocation-light
func atoi(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errNaN
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

var errNaN = &parseErr{}

type parseErr struct{}

func (*parseErr) Error() string { return "not a number" }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// sanitizeLog mirrors run.Sanitize without importing run (avoids a cycle): drop
// pre-carriage-return content and trim.
func sanitizeLog(line string) string {
	if i := strings.LastIndexByte(line, '\r'); i >= 0 {
		line = line[i+1:]
	}
	return strings.TrimRight(line, " \t")
}
