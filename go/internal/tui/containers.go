package tui

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// containerRow is one row of the Containers tab — a running container and its
// live resource use, ktop-style. The dxdfir tool containers are ephemeral
// (--rm, one per file), so this is mostly populated while a process job runs.
type containerRow struct {
	name, image, status, cpu, mem string
}

// pollContainers runs `docker ps` + `docker stats --no-stream` and returns the
// rows merged by container name, sorted. A docker error yields a single
// diagnostic row rather than failing — the tab must never take the shell down.
func pollContainers(ctx context.Context) []containerRow {
	ps, err := dockerLines(ctx, "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}")
	if err != nil {
		return []containerRow{{name: "docker unavailable", image: firstLineOf(err.Error())}}
	}
	// stats is best-effort: skip CPU/mem if it errors or times out.
	stats := map[string][2]string{}
	if sl, serr := dockerLines(ctx, "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"); serr == nil {
		for _, l := range sl {
			if f := strings.SplitN(l, "\t", 3); len(f) == 3 {
				stats[f[0]] = [2]string{f[1], f[2]}
			}
		}
	}
	var rows []containerRow
	for _, l := range ps {
		f := strings.SplitN(l, "\t", 3)
		if len(f) < 3 {
			continue
		}
		r := containerRow{name: f[0], image: f[1], status: f[2]}
		if s, ok := stats[f[0]]; ok {
			r.cpu, r.mem = s[0], s[1]
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	return rows
}

// dockerLines runs one docker command (bounded), returning its non-empty output
// lines.
func dockerLines(ctx context.Context, args ...string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "docker", args...).Output()
	if err != nil {
		// Surface docker's own stderr (e.g. "Cannot connect to the Docker daemon")
		// so the diagnostic row is useful, not a bare "exit status 1".
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("%s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
