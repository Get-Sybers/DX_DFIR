package model

// This file holds the model for the landing dashboard shown by a bare `dxdfir`
// (version + environment readiness + tracked collections + staged evidence).
// Unlike Snapshot, it is not a progress stream — it is a single point-in-time
// picture assembled once by the cli layer and rendered by tui or plain. It lives
// in the model package for the same reason Snapshot does: both presenters and
// the assembler depend on it, and it imports neither termui nor os/exec.

// CheckState is the outcome of one environment readiness probe.
type CheckState string

const (
	CheckOK   CheckState = "ok"   // precondition satisfied
	CheckWarn CheckState = "warn" // usable, but a lane/capability is unavailable
	CheckFail CheckState = "fail" // a gating precondition is not met
)

// Check is one environment readiness probe on the home dashboard.
type Check struct {
	Name   string     // short label, e.g. "docker"
	State  CheckState // ok / warn / fail
	Detail string     // resolved path or version on success; the reason on failure
	// Gate is true when this precondition must be green before `process` can run.
	// A failing non-gate check (warn) narrows what is available (a specific lane
	// or the CAR build) without blocking the pipeline as a whole.
	Gate bool
}

// CollInfo is one tracked collection summarised for the home dashboard, mirroring
// the fields `dxdfir collection list` shows.
type CollInfo struct {
	Name   string
	Total  int
	Lanes  string // "evtx:3, zeek:1", or "empty"
	Sha1   string // short sha1, or "" when the evidence is not hashed yet
	Active bool   // the selected active collection
	Tag    string // "", "unregistered", or "candidate"
}

// LaneCount is staged evidence for one processing lane over data_store/raw/.
type LaneCount struct {
	Name   string
	Count  int
	Loc    string // the raw/ subdir(s) it reads, e.g. "logs/winevt/"
	Staged bool   // Count > 0
}

// Home is the presenter-agnostic model for the landing dashboard. It is
// assembled by the cli layer (readiness probes + a collection-registry query +
// a staged-evidence walk) and rendered by the tui or plain presenter.
type Home struct {
	Version     string
	RepoRoot    string // "" when the checkout could not be located
	Checks      []Check
	Collections []CollInfo
	Lanes       []LaneCount
	// CollErr is set when the collection registry could not be read at all (e.g.
	// the processor package is not importable yet); the panel shows it INSTEAD of
	// a list.
	CollErr string
	// CollNote is an informational line shown ALONGSIDE the collection list — used
	// when the fast directory-name fallback ran because the full registry scan was
	// too slow over the evidence store (names shown, per-lane counts omitted).
	CollNote string
}

// Ready reports whether every gating check passed — i.e. the pipeline's
// preconditions for processing evidence are all met.
func (h Home) Ready() bool {
	for _, c := range h.Checks {
		if c.Gate && c.State != CheckOK {
			return false
		}
	}
	return true
}
