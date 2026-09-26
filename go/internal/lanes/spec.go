// Package lanes drives the `process` verb: it runs each evidence lane's
// ansible-playbook and reconstructs live progress by WATCHING THE FILESYSTEM —
// the only workable signal, since ansible buffers the lane's stdout until it
// exits. Each processor discovers its inputs up front (the denominator) and
// writes deterministic per-item output paths as items finish (the numerator).
package lanes

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/get-sybers/dx_dfir/go/internal/model"
)

// Spec is the static description of one process lane, derived from the role
// defaults and the tools' output-path contracts. A lane is named after the
// tool that drives it; its role is dxdfir_<Name>, its playbook
// dxdfir-process-<Name>.yml, and its output leaf data_store/processed/<OutLeaf>
// (one level deeper, <OutLeaf>/<collection>/, for a collection-scoped run).
type Spec struct {
	Name    string     // zeek, gowindowlicker, godaemonhunter, anamnesis, plaso, signatures
	Title   string     // display title
	Kind    model.Kind // gauge / heartbeat / spinner
	OutLeaf string     // processed subdir leaf under data_store/processed/
	// Aliases are the other names `process` accepts for this lane: the older
	// lane names (evtx, memory) and the image aliases GoDFIR-toolz declares
	// (windowlicker, lick, daemonhunter, hunt, log2timeline).
	Aliases []string
	// InputSubdirs are the raw/ subdirs this lane reads by default (used for the
	// denominator when NOT collection-scoped). Extensions filter what counts.
	InputSubdirs []string
	Exts         []string
	// PluginsPerImage multiplies the input count into a finer denominator
	// (anamnesis: 17 collector outputs per memory image).
	PluginsPerImage int
	// Summary is the one-line description `process -h` prints.
	Summary string
}

// Specs lists every lane in the order `process all` runs them (evidence lanes
// then the detection lane last), matching collection.LANES.
var Specs = []Spec{
	{Name: "zeek", Title: "zeek", Kind: model.KindGauge, OutLeaf: "zeek",
		InputSubdirs: []string{"pcaps"}, Exts: dotset(".pcap", ".pcapng", ".cap"),
		Summary: "PCAPs -> Zeek JSON logs"},
	{Name: "gowindowlicker", Title: "gowindowlicker", Kind: model.KindGauge, OutLeaf: "windowlicker",
		Aliases:      []string{"windowlicker", "lick", "evtx"},
		InputSubdirs: []string{"logs/winevt", "disk_images", "VM_files"},
		Exts:         append(dotset(".evtx"), imageExts()...),
		Summary:      "Windows hosts (event logs, disk images/VMs) -> goevtx + the Windows artefact parsers"},
	{Name: "godaemonhunter", Title: "godaemonhunter", Kind: model.KindGauge, OutLeaf: "daemonhunter",
		Aliases:      []string{"daemonhunter", "hunt"},
		InputSubdirs: []string{"logs/linux", "disk_images", "VM_files"},
		Exts:         nil, // a Linux host is a folder of anything; images by extension are counted through the export
		Summary:      "Linux hosts (logs, disk images/VMs) -> the daemon parsers, knowledge-enriched"},
	{Name: "anamnesis", Title: "anamnesis", Kind: model.KindGauge, OutLeaf: "anamnesis",
		Aliases:      []string{"memory"},
		InputSubdirs: []string{"memory"}, PluginsPerImage: 17,
		Exts:    dotset(".dmp", ".mem", ".lime", ".vmem", ".raw", ".dump", ".bin"),
		Summary: "memory images -> plugin JSONL"},
	{Name: "plaso", Title: "plaso", Kind: model.KindHeartbeat, OutLeaf: "log2timeline",
		Aliases:      []string{"log2timeline", "psort"},
		InputSubdirs: []string{"disk_images", "VM_files"}, Exts: imageExts(),
		Summary: "disk images/VMs -> super timeline"},
	{Name: "signatures", Title: "signatures", Kind: model.KindSpinner, OutLeaf: "detections",
		InputSubdirs: []string{"pcaps", "disk_images", "memory"}, Exts: nil,
		Summary: "yara/suricata/hayabusa over the staged evidence"},
}

// Groups are the names that expand to several lanes: `all` is every lane in
// run order; `godfir-toolz` (the retired lane that ran both matrices) is the
// two GoDFIR-toolz host lanes.
var Groups = map[string][]string{
	"all":          nil, // filled by init from Specs
	"godfir-toolz": {"gowindowlicker", "godaemonhunter"},
}

func init() {
	Groups["all"] = AllNames()
}

func imageExts() []string {
	return dotset(".e01", ".ex01", ".dd", ".raw", ".img", ".vmdk", ".vhd",
		".vhdx", ".001", ".aff4", ".vmx", ".ova")
}

// SpecByName returns the lane spec for a lane name or one of its aliases, or
// ok=false.
func SpecByName(name string) (Spec, bool) {
	for _, s := range Specs {
		if s.Name == name {
			return s, true
		}
		for _, a := range s.Aliases {
			if a == name {
				return s, true
			}
		}
	}
	return Spec{}, false
}

// Resolve expands what `process` was given — a lane name, an alias or a group
// — into the lane names to run, in run order. ok=false for an unknown name.
func Resolve(name string) ([]string, bool) {
	if names, ok := Groups[name]; ok {
		return append([]string(nil), names...), true
	}
	if s, ok := SpecByName(name); ok {
		return []string{s.Name}, true
	}
	return nil, false
}

// IsLaneWord reports whether `process` reads the word as a lane (a name, an
// alias or a group) rather than a collection.
func IsLaneWord(name string) bool {
	_, ok := Resolve(name)
	return ok
}

// AllNames returns the lane names in run order.
func AllNames() []string {
	out := make([]string, len(Specs))
	for i, s := range Specs {
		out[i] = s.Name
	}
	return out
}

// LaneWords lists every word `process` accepts as a lane — the names, then
// the aliases and groups — for help and error text.
func LaneWords() []string {
	out := AllNames()
	var extra []string
	for _, s := range Specs {
		extra = append(extra, s.Aliases...)
	}
	for g := range Groups {
		extra = append(extra, g)
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// outDir resolves the processed output directory for this lane: the leaf, or
// <leaf>/<collection> for a collection-scoped run — the same rule the roles'
// dxdfir_<lane>_collection default applies.
//
// The detection lane is the exception: its leaf holds one tree per sub-tool
// and the collection sits under EACH of them (detections/<sub-tool>/<collection>/),
// so its outDir is always the leaf and countDone scopes per sub-tool.
func (s Spec) outDir(repoRoot, collection string) string {
	if collection != "" && s.Name != "signatures" {
		return filepath.Join(repoRoot, "data_store", "processed", s.OutLeaf, collection)
	}
	return filepath.Join(repoRoot, "data_store", "processed", s.OutLeaf)
}

// countInputs counts evidence files under the given absolute input dirs matching
// this lane's extensions. Used for the denominator when not collection-scoped.
func (s Spec) countInputs(dirs []string) int {
	n := 0
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(path string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return nil
			}
			if s.matchExt(path) {
				n++
			}
			return nil
		})
	}
	return n
}

func (s Spec) matchExt(path string) bool {
	if len(s.Exts) == 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range s.Exts {
		if ext == e {
			return true
		}
	}
	return false
}

// countDone reconstructs completed units from the lane's output tree — the
// done markers each tool writes, at any depth (a collection-scoped run's
// items sit under <leaf>/<collection>/, the host lanes' under
// <subtool>/<host>/<item>/), never inside a `_`-prefixed staging directory.
func (s Spec) countDone(outDir, collection string) int {
	switch s.Name {
	case "zeek":
		// one output folder per capture; zeek.jsonl is the index that marks it done
		return countFilesNamed(outDir, "zeek.jsonl")
	case "gowindowlicker", "godaemonhunter":
		// one <item>/<subtool>.jsonl per parsed artefact (goese's per-table
		// files ride under its goese.jsonl index; the knowledge store counts too)
		return countFilesMatching(outDir, func(name string) bool {
			return strings.HasPrefix(name, "go") && strings.HasSuffix(name, ".jsonl")
		})
	case "anamnesis":
		// per (image,plugin) .jsonl; the finest gauge
		return countFilesMatching(outDir, func(name string) bool { return strings.HasSuffix(name, ".jsonl") },
			withParentNamed("plugins"))
	case "plaso":
		// completion marker per image: log2timeline.jsonl (the index, written last)
		return countFilesNamed(outDir, "log2timeline.jsonl")
	case "signatures":
		// spinner: count the terminal detection outputs that have landed
		done := 0
		for _, sub := range [][2]string{
			{"suricata", "suricata.jsonl"}, {"hayabusa", "hayabusa.jsonl"},
			{"yara", "yara.jsonl"}, {"yara", "scan.jsonl"},
		} {
			if countFilesNamed(filepath.Join(outDir, sub[0], collection), sub[1]) > 0 {
				done++
			}
		}
		return done
	default:
		return 0
	}
}

func dotset(exts ...string) []string { return exts }
