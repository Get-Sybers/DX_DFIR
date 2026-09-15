package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// kibanaStatus is one poll of the Elastic stack (stacks/elastic): Kibana's
// reachability + URL, Elasticsearch cluster health, and the dxdfir data-stream
// doc counts. A terminal can't host Kibana's web UI, so the tab answers the
// operator's real question instead — "is my evidence in Elastic yet, and how
// much" — and points at the browser URL for the rest.
type kibanaStatus struct {
	kibanaURL   string
	kibanaState string // ready | starting | down
	esState     string // green|yellow|red, "up (auth required)", or unreachable
	esDetail    string // nodes / shards, or the failure reason
	streams     []streamRow
	note        string // set when the picture is degraded (stack down, no creds)
}

// streamRow is one logs-dxdfir.* data stream and its size.
type streamRow struct {
	index, docs, size string
}

// Elastic stack endpoints — every published port is bound to 127.0.0.1 (see
// stacks/elastic/docker-compose.yml).
const (
	esURL     = "https://localhost:9200"
	kibanaURL = "http://127.0.0.1:5601"
)

// pollKibana probes the stack, bounded, degrading to a note rather than an error
// — the tab must never take the shell down. Credentials come from
// stacks/elastic/.env (never committed); without them only the unauthenticated
// posture is visible.
func pollKibana(ctx context.Context, repoRoot string) kibanaStatus {
	st := kibanaStatus{kibanaURL: kibanaURL, kibanaState: "down", esState: "unreachable"}

	switch code := curlCode(ctx, kibanaURL); {
	case code == "302" || code == "200":
		st.kibanaState = "ready"
	case code == "503":
		st.kibanaState = "starting"
	}

	user, pass, haveCreds := readElasticEnv(repoRoot)
	if !haveCreds {
		// No .env: the unauthenticated call still tells up-vs-down (security ON
		// answers "missing authentication credentials" when it is up).
		if body, err := curl(ctx, esURL, "", ""); err == nil && strings.Contains(string(body), "missing authentication") {
			st.esState = "up"
			st.esDetail = "auth required — set stacks/elastic/.env for health + doc counts"
		}
		st.note = "stacks/elastic/.env not found — showing reachability only"
		return st
	}

	health, err := curl(ctx, esURL+"/_cluster/health", user, pass)
	if err != nil {
		st.note = "elasticsearch unreachable: " + firstLineOf(err.Error()) + " — is stacks/elastic up?"
		return st
	}
	var h struct {
		Status       string `json:"status"`
		Nodes        int    `json:"number_of_nodes"`
		ActiveShards int    `json:"active_shards"`
	}
	if json.Unmarshal(health, &h) == nil && h.Status != "" {
		st.esState = h.Status // green | yellow | red
		st.esDetail = fmt.Sprintf("%d node(s), %d active shards", h.Nodes, h.ActiveShards)
	} else if strings.Contains(string(health), "missing authentication") {
		st.esState = "up"
		st.esDetail = "authentication failed — check stacks/elastic/.env credentials"
		return st
	}

	// The dxdfir evidence lands in logs-dxdfir.<type>-<namespace> data streams
	// (stacks/elastic/config/filebeat.yml). List them with doc counts.
	if body, err := curl(ctx, esURL+"/_cat/indices/logs-dxdfir*?format=json&h=index,docs.count,store.size&s=index", user, pass); err == nil {
		var idx []struct {
			Index string `json:"index"`
			Docs  string `json:"docs.count"`
			Size  string `json:"store.size"`
		}
		if json.Unmarshal(body, &idx) == nil {
			for _, r := range idx {
				st.streams = append(st.streams, streamRow{index: r.Index, docs: r.Docs, size: r.Size})
			}
		}
	}
	if len(st.streams) == 0 && st.esState != "unreachable" {
		st.note = "no logs-dxdfir.* data streams yet — process evidence and ship it (filebeat)"
	}
	return st
}

// curl runs a bounded GET against a localhost endpoint (see curlDo).
func curl(ctx context.Context, url, user, pass string) ([]byte, error) {
	return curlDo(ctx, url, user, pass, "GET", nil)
}

// curlDo runs `curl -sk` against a localhost endpoint, bounded. Credentials AND
// any request body are passed through a stdin config (-K -), so neither the
// password nor the query text ever lands on the argv / process list. Insecure
// (-k) is deliberate: the stack's cert is self-signed and the port is bound to
// loopback only.
func curlDo(ctx context.Context, url, user, pass, method string, body []byte) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	args := []string{"-sk", "--max-time", "6", "-K", "-"}
	if method != "" && method != "GET" {
		args = append(args, "-X", method)
	}
	if body != nil {
		args = append(args, "-H", "Content-Type: application/json")
	}
	args = append(args, url)

	var cfg strings.Builder // curl config on stdin: keeps password + body off argv
	if user != "" {
		fmt.Fprintf(&cfg, "user = \"%s:%s\"\n", curlEsc(user), curlEsc(pass))
	}
	if body != nil {
		fmt.Fprintf(&cfg, "data = \"%s\"\n", curlEsc(string(body)))
	}
	cmd := exec.CommandContext(cctx, "curl", args...)
	cmd.Stdin = strings.NewReader(cfg.String())
	out, err := cmd.Output()
	if err != nil {
		// Surface curl's own stderr so a query failure is legible, not "exit 22".
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("%s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	return out, nil
}

// curlEsc escapes a value for a curl config double-quoted string ("..."), so a
// credential or query containing a quote, backslash, or newline can neither break
// the config nor inject a second directive. Backslash first, then the rest;
// newlines become the \n/\r escapes curl reads back inside the quotes.
func curlEsc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

// curlCode returns just the HTTP status code of a bounded HEAD-less GET (or "000"
// when the host does not answer).
func curlCode(ctx context.Context, url string) string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "curl", "-sk", "-o", "/dev/null",
		"-w", "%{http_code}", "--max-time", "4", url).Output()
	if err != nil {
		return "000"
	}
	return strings.TrimSpace(string(out))
}

// readElasticEnv reads the Elasticsearch username/password from
// stacks/elastic/.env (the file the compose stack itself consumes). Username
// defaults to "elastic"; the boolean is false when no password is found.
func readElasticEnv(repoRoot string) (user, pass string, ok bool) {
	user = "elastic" // the stack's default; returned even when no .env is found
	if repoRoot == "" {
		return user, "", false
	}
	f, err := os.Open(filepath.Join(repoRoot, "docker", "elastic", ".env"))
	if err != nil {
		return user, "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "export "))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "ELASTICSEARCH_USERNAME":
			if v != "" {
				user = v
			}
		case "ELASTIC_PASSWORD", "ELASTICSEARCH_PASSWORD":
			if v != "" {
				pass = v
			}
		}
	}
	return user, pass, pass != ""
}

// esqlResult is one ES|QL query outcome for the Kibana tab: the result columns
// and rows, or a note explaining an empty/failed run. `ran` distinguishes "a
// query has completed" from the initial (no query yet) state.
type esqlResult struct {
	cols []string
	rows [][]string
	note string
	ran  bool
}

// runESQL runs an ES|QL query against Elasticsearch (POST /_query) and returns
// the tabular result. ES|QL replies with columns + values directly — the natural
// shape for a terminal table — so this is the query language the tab speaks.
// Degrades to a note (never a hard error) so the tab stays alive.
func runESQL(ctx context.Context, repoRoot, query string) esqlResult {
	query = strings.TrimSpace(query)
	if query == "" {
		return esqlResult{}
	}
	user, pass, ok := readElasticEnv(repoRoot)
	if !ok {
		return esqlResult{ran: true, note: "no credentials — set stacks/elastic/.env to query"}
	}
	body, _ := json.Marshal(map[string]any{"query": query})
	out, err := curlDo(ctx, esURL+"/_query?format=json", user, pass, "POST", body)
	if err != nil {
		return esqlResult{ran: true, note: "query failed: " + firstLineOf(err.Error()) + " — is stacks/elastic up?"}
	}
	return parseESQL(out)
}

// parseESQL turns an ES|QL /_query response (or an Elasticsearch error body) into
// a result. Split from runESQL so it is unit-testable without a live stack.
func parseESQL(out []byte) esqlResult {
	var r struct {
		Columns []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"columns"`
		Values [][]any `json:"values"`
		Error  *struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"error"`
	}
	if json.Unmarshal(out, &r) != nil {
		return esqlResult{ran: true, note: "unparseable response: " + firstLineOf(strings.TrimSpace(string(out)))}
	}
	if r.Error != nil && (r.Error.Reason != "" || r.Error.Type != "") {
		msg := r.Error.Reason
		if msg == "" {
			msg = r.Error.Type
		}
		return esqlResult{ran: true, note: "ES error: " + firstLineOf(msg)}
	}
	if len(r.Columns) == 0 {
		return esqlResult{ran: true, note: firstLineOf(strings.TrimSpace(string(out)))}
	}
	cols := make([]string, len(r.Columns))
	for i, c := range r.Columns {
		cols[i] = c.Name
	}
	rows := make([][]string, 0, len(r.Values))
	for _, v := range r.Values {
		row := make([]string, len(v))
		for i, cell := range v {
			row[i] = str(cell) // shared JSON-scalar renderer (timeline.go)
		}
		rows = append(rows, row)
	}
	note := ""
	if len(rows) == 0 {
		note = "0 rows"
	}
	return esqlResult{cols: cols, rows: rows, ran: true, note: note}
}
