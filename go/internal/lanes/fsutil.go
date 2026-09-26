package lanes

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// ansiRE matches ANSI/VT escape sequences; kept in step with run.Sanitize's
// regexp (this package cannot import run without a cycle).
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// readTail returns up to n filtered trailing lines of a (possibly large) log
// file: it reads only the last maxBytes, strips redraw noise, collapses runs of
// duplicate lines to "line (xN)", and keeps only lines likely to carry signal.
func readTail(path string, n, maxBytes int) []string {
	// O_NOFOLLOW: a watched output/log file is never legitimately a symlink, so
	// refuse to open (and render) one a compromised tool may have planted at a host
	// file. ELOOP => nil (no tail), same as any unreadable file.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
// everything before the last carriage return (collapsing in-place redraws to
// their final state), strip ANSI escape sequences, defuse termui's [text](style)
// markup by breaking the "](" adjacency its parser keys on, and trim — so a
// tailed log line is safe to hand straight to a termui widget.
func sanitizeLog(line string) string {
	if i := strings.LastIndexByte(line, '\r'); i >= 0 {
		line = line[i+1:]
	}
	line = ansiRE.ReplaceAllString(line, "")
	line = strings.ReplaceAll(line, "](", "] (")
	return strings.TrimRight(line, " \t")
}

// walkOpt narrows a counting walk.
type walkOpt func(path string) bool

// withParentNamed keeps only files whose parent directory has the given name.
func withParentNamed(name string) walkOpt {
	return func(path string) bool { return filepath.Base(filepath.Dir(path)) == name }
}

// countFilesMatching counts the regular files under root (any depth) whose
// base name satisfies match and every opt, never descending into a
// `_`-prefixed directory (a lane's staging area). A missing root counts zero.
func countFilesMatching(root string, match func(name string) bool, opts ...walkOpt) int {
	n := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if !match(d.Name()) {
			return nil
		}
		for _, o := range opts {
			if !o(path) {
				return nil
			}
		}
		n++
		return nil
	})
	return n
}

// countFilesNamed counts the files under root (any depth) called exactly name.
func countFilesNamed(root, name string) int {
	return countFilesMatching(root, func(n string) bool { return n == name })
}

// largestFileMatching returns the size (bytes) of the largest file under root
// (any depth) whose name satisfies match — plaso's "still alive" heartbeat
// (the growing .plaso db).
func largestFileMatching(root string, match func(name string) bool) int64 {
	var max int64
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !match(d.Name()) {
			return nil
		}
		if fi, err := d.Info(); err == nil && fi.Size() > max {
			max = fi.Size()
		}
		return nil
	})
	return max
}

// newestFileMatching returns the most recently modified file under root (any
// depth) whose name satisfies match, or "".
func newestFileMatching(root string, match func(name string) bool) string {
	var newest string
	var newestMod int64 = -1
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !match(d.Name()) {
			return nil
		}
		if fi, err := d.Info(); err == nil && fi.ModTime().UnixNano() > newestMod {
			newestMod = fi.ModTime().UnixNano()
			newest = path
		}
		return nil
	})
	return newest
}
