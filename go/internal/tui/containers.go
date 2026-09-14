package tui

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// containerRow is one row of the Containers tab — a running container and its
// live resource use, ktop-style. The dxdfir tool containers are ephemeral
// (--rm, one per file), so this is mostly populated while a process job runs.
// cpuPct/memPct are the parsed percentages that drive the aggregate gauges; the
// cpu/mem strings are docker's own rendering for the table.
type containerRow struct {
	name, image, status, cpu, mem string
	cpuPct, memPct                float64
}

// pollContainers runs `docker ps` + `docker stats --no-stream` and returns the
// rows merged by container name, sorted. A docker error yields a single
// diagnostic row rather than failing — the tab must never take the shell down.
func pollContainers(ctx context.Context) []containerRow {
	ps, err := dockerLines(ctx, "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}")
	if err != nil {
		return []containerRow{{name: "docker unavailable", image: firstLineOf(err.Error())}}
	}
	// stats is best-effort: skip resource use if it errors or times out.
	type stat struct{ cpu, mem, memPct string }
	stats := map[string]stat{}
	if sl, serr := dockerLines(ctx, "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"); serr == nil {
		for _, l := range sl {
			if f := strings.SplitN(l, "\t", 4); len(f) == 4 {
				stats[f[0]] = stat{cpu: f[1], mem: f[2], memPct: f[3]}
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
			r.cpu, r.mem = s.cpu, s.mem
			r.cpuPct = parsePct(s.cpu)
			r.memPct = parsePct(s.memPct)
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	return rows
}

// parsePct reads a docker percentage like "12.34%" into a float; anything
// unparseable (missing stats, "--") reads as 0.
func parsePct(s string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%")), 64)
	if err != nil {
		return 0
	}
	return v
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
