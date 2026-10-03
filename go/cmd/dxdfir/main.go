// Command dxdfir is the Go/termui front-end for the DX_DFIR forensic pipeline.
// It owns only the user-facing verbs and their presentation; the heavy work
// stays in the get_sybers.dxdfir Ansible collection and the hardened tool
// containers it runs, which this binary drives by shelling out.
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/Get-Sybers/DX_DFIR/go/internal/cli"
)

// version is the project version — this constant is its one home.
const version = "0.6.0"

// buildVersion augments the semantic version with the short VCS revision and the
// dirty flag that `go build` embeds in the binary. The dashboards show it at the
// top, so a rebuilt binary is distinguishable at a glance — a plain "0.6.0" is
// identical across rebuilds and can't tell a fresh build from a stale one.
func buildVersion() string {
	v := version
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 7 {
				rev = s.Value[:7]
			} else {
				rev = s.Value
			}
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	switch {
	case rev != "" && dirty:
		v += " (" + rev + ", dirty)"
	case rev != "":
		v += " (" + rev + ")"
	case dirty:
		v += " (dirty)"
	}
	return v
}

func main() {
	root := cli.NewRootCmd(buildVersion())
	if err := root.Execute(); err != nil {
		var ee cli.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
