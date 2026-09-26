// Command dxdfir is the Go/termui front-end for the DX_DFIR forensic pipeline.
// It owns only the user-facing verbs and their presentation; the heavy work
// stays in the get_sybers.dxdfir Ansible collection and the hardened tool
// containers it runs, which this binary drives by shelling out.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/get-sybers/dx_dfir/go/internal/cli"
)

// version is the project version — this constant is its one home.
const version = "0.6.0"

func main() {
	root := cli.NewRootCmd(version)
	if err := root.Execute(); err != nil {
		var ee cli.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
