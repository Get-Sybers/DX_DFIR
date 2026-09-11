// Package lanes drives the `process` verb: it runs each evidence lane's
// ansible-playbook and reconstructs live progress by WATCHING THE FILESYSTEM —
// the only workable signal, since ansible buffers the lane's stdout until it
// exits. Each processor discovers its inputs up front (the denominator) and
// writes deterministic per-item output paths as items finish (the numerator).
package lanes

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/get-sybers/dx_dfir/go/internal/model"
)

// Spec is the static description of one process lane, derived from the role
// defaults and the processors' output-path contracts.
type Spec struct {
	Name    string     // zeek, evtx, volatility, plaso, zimmerman, signatures
	Title   string     // display title
	Kind    model.Kind // gauge / heartbeat / spinner
	OutLeaf string     // processed subdir leaf for pipeline=elastic
	// InputSubdirs are the raw/ subdirs this lane reads by default (used for the
	// denominator when NOT collection-scoped). Extensions filter what counts.
	InputSubdirs []string
	Exts         []string
	// PluginsPerImage multiplies the input count into a finer denominator
	// (volatility: 18 plugin outputs per memory image).
	PluginsPerImage int
}

// Specs lists every lane in the order `process all` runs them (evidence lanes
// then the detection lane last), matching collection.LANES.
var Specs = []Spec{
	{Name: "zeek", Title: "zeek", Kind: model.KindGauge, OutLeaf: "zeek",
		InputSubdirs: []string{"pcaps"}, Exts: dotset(".pcap", ".pcapng", ".cap")},
	{Name: "evtx", Title: "evtx", Kind: model.KindGauge, OutLeaf: "windows_logs",
		InputSubdirs: []string{"logs/winevt"}, Exts: dotset(".evtx")},
	{Name: "volatility", Title: "volatility", Kind: model.KindGauge, OutLeaf: "volatility",
		InputSubdirs: []string{"memory"}, PluginsPerImage: 18,
		Exts: dotset(".dmp", ".mem", ".lime", ".vmem", ".raw", ".dump", ".bin")},
	{Name: "plaso", Title: "plaso", Kind: model.KindHeartbeat, OutLeaf: "log2timeline",
		InputSubdirs: []string{"disk_images", "VM_files"}, Exts: imageExts()},
	{Name: "zimmerman", Title: "zimmerman", Kind: model.KindGauge, OutLeaf: "zimmerman",
		InputSubdirs: []string{"disk_images", "VM_files"}, Exts: imageExts()},
	{Name: "signatures", Title: "signatures", Kind: model.KindSpinner, OutLeaf: "signatures",
		InputSubdirs: []string{"pcaps", "disk_images", "memory"}, Exts: nil},
}

func imageExts() []string {
	return dotset(".e01", ".ex01", ".dd", ".raw", ".img", ".vmdk", ".vhd",
		".vhdx", ".001", ".aff4", ".vmx", ".ova")
}

// SpecByName returns the lane spec, or ok=false.
func SpecByName(name string) (Spec, bool) {
	for _, s := range Specs {
		if s.Name == name {
			return s, true
		}
	}
	return Spec{}, false
}

// AllNames returns the lane names in run order.
func AllNames() []string {
	out := make([]string, len(Specs))
	for i, s := range Specs {
		out[i] = s.Name
	}
	return out
}

// outDir resolves the processed output directory for this lane and pipeline;
// sofelk nests the same leaf under processed/sofelk/.
func (s Spec) outDir(repoRoot, pipeline string) string {
	if pipeline == "sofelk" {
		return filepath.Join(repoRoot, "data_store", "processed", "sofelk", s.OutLeaf)
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

// countDone reconstructs completed units from the lane's output tree.
func (s Spec) countDone(outDir string) int {
	switch s.Name {
	case "zeek":
		// one output folder per capture, populated with *.json on success
		return len(uniqueParents(glob(outDir, "*", "*.json")))
	case "evtx":
		return len(glob(outDir, "*", "*_EvtxECmd_Output.json"))
	case "volatility":
		// per (image,plugin) .jsonl; the finest gauge
		return len(glob(outDir, "*", "plugins", "*.jsonl"))
	case "plaso":
		// completion marker per image (.host written last)
		return len(glob(outDir, "plaso", "*.host"))
	case "zimmerman":
		// one host dir per image with any output
		return len(hostDirsWithOutput(outDir))
	case "signatures":
		// spinner: count the terminal detection outputs that have landed
		done := 0
		if len(glob(outDir, "suricata", "*.eve.jsonl")) > 0 {
			done++
		}
		for _, rel := range [][]string{
			{"hayabusa", "timeline.jsonl"},
			{"yara", "matches.jsonl"},
			{"yara", "disk.jsonl"},
			{"yara", "memory.jsonl"},
		} {
			if fileNonEmpty(filepath.Join(append([]string{outDir}, rel...)...)) {
				done++
			}
		}
		return done
	default:
		return 0
	}
}

func dotset(exts ...string) []string { return exts }
