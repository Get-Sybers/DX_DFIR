// Package collection is the native-Go reader for the DX_DFIR collection layer:
// the SQLite registry at data_store/raw/collections/.registry.db plus the
// on-disk lane subdirs and .collection.hashes manifest. It reimplements the
// READ contract the front-end previously obtained by shelling out to
// `python -m get_sybers_dxdfir.collection {status,lanes,state}` — same JSON
// shapes, same lane scoping, same file-counting semantics — but reads the DB
// directly and walks the lanes concurrently, which is the win over a large or
// networked evidence store where the Python serial os.walk cost >60s.
//
// Reads only. Writes (register/sort/hash/select/unselect/unregister) stay in the
// Python module for now; see epic #174. The Go reader and the Python writer
// share the registry schema as a contract during that transition.
package collection

import (
	"path"
	"path/filepath"
	"regexp"

	"github.com/get-sybers/dx_dfir/go/internal/identify"
)

// Lane mirrors get_sybers_dxdfir.collection.Lane: a processing lane, the raw/
// subdirs it reads, and the Ansible input-dir var(s) parallel to those subdirs.
type Lane struct {
	Name      string
	Subdirs   []string
	InputVars []string
}

// LANES is the lane -> sorted-subdir -> Ansible input-var map (order =
// `process all` order). Detection is the processors' job; this only says where
// a lane reads. Every input dir a lane role declares must be listed here, or a
// collection-scoped run falls back to that input's LOOSE default and reads
// evidence from outside the collection.
var LANES = []Lane{
	{"zeek", []string{"pcaps"}, []string{"dxdfir_zeek_pcap_dir"}},
	{"evtx", []string{"logs/winevt"}, []string{"dxdfir_evtx_evtx_dir"}},
	{"memory", []string{"memory"}, []string{"dxdfir_memory_memory_dir"}},
	{"plaso", []string{"disk_images", "VM_files"},
		[]string{"dxdfir_plaso_input_dir", "dxdfir_plaso_vm_dir"}},
	{"godfir-toolz", []string{"disk_images", "VM_files"},
		[]string{"dxdfir_godfir_toolz_input_dir", "dxdfir_godfir_toolz_vm_dir"}},
	{"signatures", []string{"pcaps", "disk_images", "memory", "logs/winevt", "other_raw_data"},
		[]string{"dxdfir_signatures_pcap_dir", "dxdfir_signatures_disk_dir",
			"dxdfir_signatures_memory_dir", "dxdfir_signatures_evtx_dir",
			"dxdfir_signatures_files_dir"}},
}

// evidenceSubdirs returns the canonical lane subdirs a collection materialises,
// counts, and sorts into — every lane's subdir plus the catch-all, in taxonomy
// precedence order. Derived from the shared evidence taxonomy (evidence-taxonomy/),
// never hardcoded. Returns nil when the taxonomy can't be loaded, so callers
// degrade to zero counts rather than crash.
func evidenceSubdirs(repoRoot string) []string {
	tax, err := identify.Load(repoRoot)
	if err != nil {
		return nil
	}
	return tax.Subdirs()
}

// evidenceTypeInfo is one collection-summary bucket: a lane subdir and the short
// label shown for it (the subdir's leaf, e.g. "logs/winevt" -> "winevt").
type evidenceTypeInfo struct{ subdir, label string }

// evidenceTypesFor returns the summary buckets (lane subdirs + catch-all, in
// taxonomy order) with their display labels. The KIND identify sorted a file
// into — not the processing lane(s) that later read it.
func evidenceTypesFor(repoRoot string) []evidenceTypeInfo {
	subs := evidenceSubdirs(repoRoot)
	out := make([]evidenceTypeInfo, 0, len(subs))
	for _, s := range subs {
		out = append(out, evidenceTypeInfo{s, path.Base(s)})
	}
	return out
}

// Registry / dropzone locations and control-file names — mirror collection.py.
const (
	registryName = ".registry.db"
	markerName   = ".collection"
	logName      = ".collection.log"
	manifestName = ".collection.hashes"
)

var (
	collectionsRel = []string{"data_store", "raw", "collections"}
	dropzoneRel    = []string{"data_store", "raw", "sort"}
	nameRe         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// TypeCount is one evidence-type bucket in a collection summary: a short lane
// label (the subdir leaf) and how many files identify sorted into it.
type TypeCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// Summary is the per-collection status row. Types breaks the evidence down by
// identified KIND — the canonical lanes a file's content sorts it into, in
// taxonomy order, nonzero only — and Total is the distinct evidence-file count
// (the sum of Types; each file is counted once, under its most specific lane).
type Summary struct {
	Name  string      `json:"name"`
	Types []TypeCount `json:"types"`
	Total int         `json:"total"`
	Sha1  *string     `json:"sha1"`
}

// Status mirrors `collection status`.
type Status struct {
	Active       string    `json:"active"`
	Registered   []Summary `json:"registered"`
	Unregistered []Summary `json:"unregistered"`
	Candidates   []string  `json:"candidates"`
}

// LaneInput mirrors one row of `collection lanes`.
type LaneInput struct {
	Lane  string `json:"lane"`
	Var   string `json:"var"`
	Dir   string `json:"dir"`
	Count int    `json:"count"`
}

// Lanes mirrors `collection lanes`.
type Lanes struct {
	Name   string      `json:"name"`
	Inputs []LaneInput `json:"inputs"`
}

// State mirrors `collection state`.
type State struct {
	Name       string `json:"name"`
	Registered bool   `json:"registered"`
	Detected   bool   `json:"detected"`
	Exists     bool   `json:"exists"`
}

// ValidName is collection.py's valid_name — the single choke point that keeps a
// name inside collections/ (no traversal, no absolute/`.`/`..`).
func ValidName(name string) bool {
	return name != "." && name != ".." && nameRe.MatchString(name)
}

func collectionsRoot(repoRoot string) string {
	return filepath.Join(append([]string{repoRoot}, collectionsRel...)...)
}

func dropzoneRoot(repoRoot string) string {
	return filepath.Join(append([]string{repoRoot}, dropzoneRel...)...)
}

// collectionDir returns the collection's directory, or ok=false for an invalid
// name (mirrors collection_dir's validation choke point).
func collectionDir(repoRoot, name string) (string, bool) {
	if !ValidName(name) {
		return "", false
	}
	return filepath.Join(collectionsRoot(repoRoot), name), true
}
