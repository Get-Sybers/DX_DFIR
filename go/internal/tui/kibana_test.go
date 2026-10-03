package tui

import "testing"

func TestParseESQL(t *testing.T) {
	// A normal ES|QL result: columns + values, mixed scalar types.
	body := []byte(`{"columns":[{"name":"host.name","type":"keyword"},{"name":"count","type":"long"}],` +
		`"values":[["HOST1",42],["HOST2",7]]}`)
	r := parseESQL(body)
	if !r.ran || r.note != "" {
		t.Fatalf("clean result: ran=%v note=%q", r.ran, r.note)
	}
	if len(r.cols) != 2 || r.cols[0] != "host.name" || r.cols[1] != "count" {
		t.Fatalf("cols = %v", r.cols)
	}
	if len(r.rows) != 2 || r.rows[0][0] != "HOST1" || r.rows[0][1] != "42" {
		t.Fatalf("rows = %v", r.rows)
	}
}

func TestParseESQLError(t *testing.T) {
	body := []byte(`{"error":{"type":"verification_exception","reason":"Unknown index [nope]"},"status":400}`)
	r := parseESQL(body)
	if !r.ran || len(r.cols) != 0 {
		t.Fatalf("error result should carry no columns: %+v", r)
	}
	if want := "ES error: Unknown index [nope]"; r.note != want {
		t.Errorf("note = %q, want %q", r.note, want)
	}
}

func TestParseESQLEmpty(t *testing.T) {
	r := parseESQL([]byte(`{"columns":[{"name":"x","type":"long"}],"values":[]}`))
	if r.note != "0 rows" {
		t.Errorf("empty values note = %q, want %q", r.note, "0 rows")
	}
	if len(r.cols) != 1 {
		t.Errorf("columns should still be reported: %v", r.cols)
	}
}

func TestCurlEsc(t *testing.T) {
	// A value with every special char must not break out of the config quotes.
	got := curlEsc("a\"b\\c\nd")
	if want := `a\"b\\c\nd`; got != want {
		t.Errorf("curlEsc = %q, want %q", got, want)
	}
}
