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

// kibanaStatus is one poll of the Elastic stack (docker/elastic): Kibana's
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
// docker/elastic/docker-compose.yml).
const (
	esURL     = "https://localhost:9200"
	kibanaURL = "http://127.0.0.1:5601"
)

// pollKibana probes the stack, bounded, degrading to a note rather than an error
// — the tab must never take the shell down. Credentials come from
// docker/elastic/.env (never committed); without them only the unauthenticated
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
			st.esDetail = "auth required — set docker/elastic/.env for health + doc counts"
		}
		st.note = "docker/elastic/.env not found — showing reachability only"
		return st
	}

	health, err := curl(ctx, esURL+"/_cluster/health", user, pass)
	if err != nil {
		st.note = "elasticsearch unreachable: " + firstLineOf(err.Error()) + " — is docker/elastic up?"
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
		st.esDetail = "authentication failed — check docker/elastic/.env credentials"
		return st
	}

	// The dxdfir evidence lands in logs-dxdfir.<type>-<namespace> data streams
	// (docker/elastic/config/filebeat.yml). List them with doc counts.
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

// curl runs `curl -sk` against a localhost endpoint, bounded. Credentials, when
// given, are passed via a stdin config (-K -) so the password never lands on the
// argv / process list. Insecure (-k) is deliberate: the stack's cert is
// self-signed and the port is bound to loopback only.
func curl(ctx context.Context, url, user, pass string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "curl", "-sk", "--max-time", "4", "-K", "-", url)
	cfg := "" // -K - with empty stdin is a no-op; auth added only when present
	if user != "" {
		cfg = fmt.Sprintf("user = \"%s:%s\"\n", user, pass)
	}
	cmd.Stdin = strings.NewReader(cfg)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
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
// docker/elastic/.env (the file the compose stack itself consumes). Username
// defaults to "elastic"; the boolean is false when no password is found.
func readElasticEnv(repoRoot string) (user, pass string, ok bool) {
	if repoRoot == "" {
		return "", "", false
	}
	f, err := os.Open(filepath.Join(repoRoot, "docker", "elastic", ".env"))
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	user = "elastic"
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
