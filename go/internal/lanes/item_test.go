package lanes

import "testing"

func TestItemName(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"changed: [localhost] => (item=/data_store/raw/logs/winevt/WS01/Security.evtx)", "Security.evtx", true},
		{"ok: [localhost] => (item=/raw/pcaps/capture.pcapng)", "capture.pcapng", true},
		{"failed: [localhost] => (item=WS01)", "WS01", true},
		{"ok: [localhost] => (item={'name': 'x'})", "", false}, // looped dict: skip
		{"TASK [godfir_run : parse] ***", "", false},           // not a result line
		{"PLAY RECAP ***", "", false},
	}
	for _, c := range cases {
		got, ok := itemName(c.line)
		if ok != c.ok || got != c.want {
			t.Errorf("itemName(%q) = (%q, %v), want (%q, %v)", c.line, got, ok, c.want, c.ok)
		}
	}
}
