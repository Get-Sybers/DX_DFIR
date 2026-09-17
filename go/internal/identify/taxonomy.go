package identify

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// The evidence taxonomy is the single source of truth for the raw/ lanes: one
// YAML per lane under <repo>/evidence-taxonomy/, plus an _index.yml giving the
// precedence order and the catch-all subdir. It is shared with the Ansible roles
// (their raw input-dir defaults), so a file's sort destination and the directory
// a processor reads can never drift. A file's identity is its CONTENT: Classify
// tries every lane's magic signatures in precedence order first, falls back to
// extension claims, and routes anything left to the catch-all — never dropping a
// file. The magic bytes live in the YAML; only a handful of signatures that need
// real logic (a text descriptor, an end-of-file footer, a zip member probe) are
// dispatched to Go by a `kind: special:*` tag.

const (
	// maxScan bounds the window searched for an `offset: any` signature.
	maxScan = 1 << 16
	taxDir  = "evidence-taxonomy"
)

// Signature is one content-magic pattern for a lane, loaded from a lane YAML.
type Signature struct {
	Hex    string `yaml:"hex"`
	Offset any    `yaml:"offset"` // int, or the string "any"
	Kind   string `yaml:"kind"`   // "special:<name>" => Go logic; else generic match
	Ext    string `yaml:"ext"`    // informational (the gist's file_extension)
	Desc   string `yaml:"desc"`   // informational

	pattern []byte // expected bytes, already AND-ed with mask (wildcards => 0)
	mask    []byte // 0xFF for a fixed byte, 0x00 for an `nn` wildcard
	off     int    // byte offset (only for generic, non-scan signatures)
	scan    bool   // offset == "any": search a bounded window
}

// Lane is one evidence-type lane: where it files (Subdir), the extensions it
// claims as a fallback, its content signatures, and — for multi-file evidence
// sets — the marker that identifies a whole directory as one set.
type Lane struct {
	Name       string      `yaml:"name"`
	Subdir     string      `yaml:"subdir"`
	Ext        []string    `yaml:"ext"`
	SetFolder  bool        `yaml:"set_folder"`
	SetMarker  []string    `yaml:"set_marker"`
	Signatures []Signature `yaml:"signatures"`
}

// Taxonomy is the loaded evidence taxonomy, lanes in precedence order.
type Taxonomy struct {
	CatchAll string // catch-all subdir for files nothing else claims
	Order    []string
	Lanes    []*Lane
}

type indexFile struct {
	CatchAllSubdir string   `yaml:"catch_all_subdir"`
	Order          []string `yaml:"order"`
}

type loadResult struct {
	t   *Taxonomy
	err error
}

var taxCache sync.Map // dir -> loadResult

// Load reads the taxonomy under <repoRoot>/evidence-taxonomy/. Results are cached
// per directory, so a caller may Load once per operation and classify many files.
func Load(repoRoot string) (*Taxonomy, error) {
	return LoadFromDir(filepath.Join(repoRoot, taxDir))
}

// LoadFromDir reads the taxonomy from an explicit directory (used by tests).
func LoadFromDir(dir string) (*Taxonomy, error) {
	if v, ok := taxCache.Load(dir); ok {
		r := v.(loadResult)
		return r.t, r.err
	}
	t, err := loadFromDir(dir)
	taxCache.Store(dir, loadResult{t, err})
	return t, err
}

func loadFromDir(dir string) (*Taxonomy, error) {
	idxRaw, err := os.ReadFile(filepath.Join(dir, "_index.yml"))
	if err != nil {
		return nil, fmt.Errorf("evidence taxonomy: %w", err)
	}
	var idx indexFile
	if err := yaml.Unmarshal(idxRaw, &idx); err != nil {
		return nil, fmt.Errorf("evidence taxonomy _index.yml: %w", err)
	}
	if idx.CatchAllSubdir == "" {
		return nil, fmt.Errorf("evidence taxonomy _index.yml: catch_all_subdir is required")
	}
	t := &Taxonomy{CatchAll: idx.CatchAllSubdir, Order: idx.Order}
	for _, name := range idx.Order {
		laneRaw, err := os.ReadFile(filepath.Join(dir, name+".yml"))
		if err != nil {
			return nil, fmt.Errorf("evidence taxonomy lane %q: %w", name, err)
		}
		var lane Lane
		if err := yaml.Unmarshal(laneRaw, &lane); err != nil {
			return nil, fmt.Errorf("evidence taxonomy %s.yml: %w", name, err)
		}
		if lane.Subdir == "" {
			return nil, fmt.Errorf("evidence taxonomy %s.yml: subdir is required", name)
		}
		for i := range lane.Signatures {
			if err := lane.Signatures[i].compile(); err != nil {
				return nil, fmt.Errorf("evidence taxonomy %s.yml signature %d: %w", name, i, err)
			}
		}
		t.Lanes = append(t.Lanes, &lane)
	}
	return t, nil
}

// compile turns a signature's textual hex/offset into a byte pattern + mask and a
// resolved offset. `nn` (any case) is a wildcard byte; `offset: any` triggers a
// bounded scan. Signatures with a `kind` are dispatched to a Go detector instead.
func (s *Signature) compile() error {
	switch v := s.Offset.(type) {
	case nil:
		s.off = 0
	case int:
		s.off = v
	case string:
		if strings.EqualFold(v, "any") {
			s.scan = true
		} else {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("bad offset %q", v)
			}
			s.off = n
		}
	default:
		return fmt.Errorf("bad offset type %T", v)
	}
	for _, tok := range strings.Fields(s.Hex) {
		if strings.EqualFold(tok, "nn") {
			s.pattern = append(s.pattern, 0x00)
			s.mask = append(s.mask, 0x00)
			continue
		}
		b, err := strconv.ParseUint(tok, 16, 8)
		if err != nil {
			return fmt.Errorf("bad hex byte %q", tok)
		}
		s.pattern = append(s.pattern, byte(b))
		s.mask = append(s.mask, 0xFF)
	}
	if s.Kind == "" && len(s.pattern) == 0 {
		return fmt.Errorf("empty hex with no kind")
	}
	return nil
}

// match reports whether path carries this signature.
func (s *Signature) match(path string) bool {
	if s.Kind != "" {
		return matchSpecial(s.Kind, path)
	}
	if s.scan {
		return scanFor(path, s.pattern, s.mask)
	}
	if s.off < 0 {
		return false // negative offsets are only meaningful to special detectors
	}
	buf, ok := readAt(path, s.off, len(s.pattern))
	if !ok {
		return false
	}
	return maskedEqual(buf, s.pattern, s.mask)
}

// Classify types a file by content, in precedence order: any lane's magic
// signature (→ "magic"), else the first lane whose extension claims the name
// (→ "ext"), else the catch-all subdir (→ "catch-all"). It never returns "".
func (t *Taxonomy) Classify(path string) (subdir, detectedBy string) {
	for _, lane := range t.Lanes {
		for i := range lane.Signatures {
			if lane.Signatures[i].match(path) {
				return lane.Subdir, "magic"
			}
		}
	}
	lower := strings.ToLower(filepath.Base(path))
	for _, lane := range t.Lanes {
		for _, e := range lane.Ext {
			if strings.HasSuffix(lower, strings.ToLower(e)) {
				return lane.Subdir, "ext"
			}
		}
	}
	return t.CatchAll, "catch-all"
}

// SetLaneForDir returns the lane a whole directory should move into as one intact
// evidence set — when the directory holds a file matching a lane's set_marker
// (e.g. a VM export folder with a .vmx). Returns nil when the directory is not a
// recognised set and should be descended file-by-file.
func (t *Taxonomy) SetLaneForDir(dir string) *Lane {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, lane := range t.Lanes {
		if len(lane.SetMarker) == 0 {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			lower := strings.ToLower(e.Name())
			for _, m := range lane.SetMarker {
				if strings.HasSuffix(lower, strings.ToLower(m)) {
					return lane
				}
			}
		}
	}
	return nil
}

// Subdirs returns every lane subdir plus the catch-all, deepest-first so a
// longest-prefix match assigns a file to its most specific lane.
func (t *Taxonomy) Subdirs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, lane := range t.Lanes {
		add(lane.Subdir)
	}
	add(t.CatchAll)
	return out
}
