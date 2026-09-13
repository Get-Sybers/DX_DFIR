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
	"path/filepath"
	"regexp"
)

// Lane mirrors get_sybers_dxdfir.collection.Lane: a processing lane, the raw/
// subdirs it reads, and the Ansible input-dir var(s) parallel to those subdirs.
type Lane struct {
	Name      string
	Subdirs   []string
	InputVars []string
}

// LANES mirrors the Python LANES tuple exactly (order = `process all` order).
// Detection is the processors' job; this only says where a lane reads.
var LANES = []Lane{
	{"zeek", []string{"pcaps"}, []string{"dxdfir_zeek_pcap_dir"}},
	{"evtx", []string{"logs/winevt"}, []string{"dxdfir_evtx_evtx_dir"}},
	{"volatility", []string{"memory"}, []string{"dxdfir_volatility_memory_dir"}},
	{"plaso", []string{"disk_images", "VM_files"},
		[]string{"dxdfir_plaso_input_dir", "dxdfir_plaso_vm_dir"}},
	{"zimmerman", []string{"disk_images", "VM_files"},
		[]string{"dxdfir_zimmerman_input_dir", "dxdfir_zimmerman_vm_dir"}},
	{"signatures", []string{"pcaps", "disk_images", "memory"},
		[]string{"dxdfir_signatures_pcap_dir", "dxdfir_signatures_disk_dir",
			"dxdfir_signatures_memory_dir"}},
}

// laneSubdirs is the set of raw/ subdirs a collection materialises — the union
// walked once per collection so per-lane counts are summed without re-walking a
// shared subdir (disk_images feeds plaso, zimmerman AND signatures).
var laneSubdirs = []string{"pcaps", "logs/winevt", "memory", "disk_images", "VM_files"}

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

// Summary mirrors the Python per-collection summary (status rows). JSON tags
// match the retired subprocess contract so the cli's alias types stay valid.
type Summary struct {
	Name  string         `json:"name"`
	Lanes map[string]int `json:"lanes"`
	Total int            `json:"total"`
	Sha1  *string        `json:"sha1"`
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
