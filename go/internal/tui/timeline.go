package tui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// timelineRow is one entry of the byakugan behaviour timeline — a CAR object
// event or a relationship edge, already flattened for display.
type timelineRow struct {
	ts, kind, object, host, summary string
}

// timeline default location (dxdfir_byakugan role): the CAR stores + their unified,
// time-ordered timeline.jsonl land under data_store/processed/byakugan.
const carSubdir = "data_store/processed/byakugan"

// readTimeline reads the byakugan behaviour timeline from every timeline.jsonl
// under data_store/processed/byakugan (one per source, plus an aggregate), newest
// event first, capped. It is a pure on-disk read — the timeline is built by the
// car lane (byakugan.timeline), not by this tab — and degrades to a note rather
// than an error when nothing has been built yet.
func readTimeline(repoRoot string, limit int) ([]timelineRow, string) {
	if repoRoot == "" {
		return nil, "repo not located — cannot find the CAR timeline"
	}
	carDir := filepath.Join(repoRoot, carSubdir)
	files := findTimelines(carDir)
	if len(files) == 0 {
		return nil, "no CAR timeline yet — run `process`, then the car lane (dxdfir_byakugan timeline)"
	}

	var rows []timelineRow
	for _, f := range files {
		rows = append(rows, parseTimeline(f)...)
	}
	if len(rows) == 0 {
		return nil, "CAR timeline is present but empty"
	}
	// Newest first (the on-disk files are ascending); string-compare is right for
	// same-shaped ISO-8601 stamps and good enough for a glance across sources.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ts > rows[j].ts })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, ""
}

// maxTimelineFiles bounds the walk — far above any real per-source count, a guard
// against a pathological tree rather than an expected limit.
const maxTimelineFiles = 256

// findTimelines returns the timeline.jsonl files under dir (the aggregate at the
// root included), the walk stopped once maxTimelineFiles are collected.
func findTimelines(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip it, never abort the walk
		}
		// Skip a symlinked timeline.jsonl: a CAR-tree entry is never legitimately a
		// symlink, so following one would render an arbitrary host file into the TUI.
		if !d.IsDir() && d.Type()&fs.ModeSymlink == 0 && d.Name() == "timeline.jsonl" {
			out = append(out, p)
			if len(out) >= maxTimelineFiles {
				return filepath.SkipAll
			}
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// parseTimeline reads one timeline.jsonl, one JSON entry per line. A malformed
// line is skipped, never fatal — a single bad record must not blank the tab.
func parseTimeline(path string) []timelineRow {
	// O_NOFOLLOW: refuse a symlinked timeline.jsonl (ELOOP => skip) so a planted
	// link to a host file is never read into the TUI.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	var rows []timelineRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // CAR rows carry `native`; allow long lines
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		rows = append(rows, timelineEntry(e))
	}
	return rows
}

// timelineEntry flattens one CAR timeline record into a display row. Object
// events summarise the entity (process → exe + command line, flow → src→dest,
// file → path); relationship edges read source →verb→ target.
func timelineEntry(e map[string]any) timelineRow {
	ts := str(e["timestamp"])
	kind := str(e["kind"])
	host := firstNonEmpty(str(e["hostname"]), str(e["fqdn"]), str(e["source_host"]))

	if kind == "relationship" {
		obj := "→ " + str(e["relationship"])
		summary := fmt.Sprintf("%s %s→ %s", str(e["source_object"]), relArrow(e), str(e["target_object"]))
		if m := str(e["method"]); m != "" {
			summary += "  (" + m + ")"
		}
		return timelineRow{ts: ts, kind: kind, object: obj, host: host, summary: summary}
	}

	object := str(e["object"])
	return timelineRow{ts: ts, kind: firstNonEmpty(kind, "object"), object: object, host: host, summary: objectSummary(object, e)}
}

// objectSummary builds the human line for a CAR object event from whichever
// fields are populated, specialised for the common object types.
func objectSummary(object string, e map[string]any) string {
	switch object {
	case "process":
		return firstNonEmpty(
			joinNonEmpty(" ", str(e["exe"]), str(e["command_line"])),
			str(e["image_path"]), str(e["command_line"]))
	case "flow":
		src := joinHostPort(str(e["src_ip"]), str(e["src_port"]))
		dst := joinHostPort(str(e["dest_ip"]), str(e["dest_port"]))
		proto := firstNonEmpty(str(e["application_protocol"]), str(e["transport_protocol"]))
		return strings.TrimSpace(fmt.Sprintf("%s → %s %s", src, dst, proto))
	case "file":
		return firstNonEmpty(str(e["file_path"]), str(e["file_name"]))
	}
	// Unknown object: surface a few identifying fields rather than nothing.
	return joinNonEmpty("  ", str(e["command_line"]), str(e["file_path"]),
		str(e["dest_ip"]), str(e["user"]))
}

func relArrow(e map[string]any) string {
	if c := str(e["confidence"]); c != "" {
		return fmt.Sprintf("%s@%s ", str(e["relationship"]), c)
	}
	return str(e["relationship"]) + " "
}

// str renders a JSON value as a trimmed string (numbers come back as float64).
func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		return fmt.Sprintf("%t", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func joinNonEmpty(sep string, vals ...string) string {
	var keep []string
	for _, v := range vals {
		if v != "" {
			keep = append(keep, v)
		}
	}
	return strings.Join(keep, sep)
}

func joinHostPort(host, port string) string {
	if host == "" {
		return ""
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}
