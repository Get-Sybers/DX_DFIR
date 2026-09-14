package identify

import (
	"os"
	"path/filepath"
	"testing"
)

// TestClassify was lifted verbatim from the collection package's test when the
// classifier moved here — the sort-time behaviour must stay byte-for-byte.
func TestClassify(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ewf := append([]byte{0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00, 0x00}, []byte{0x01, 0x00}...) // EVF hdr + seg=1
	cases := []struct {
		file       string
		data       []byte
		wantSubdir string
		wantBy     string
	}{
		{"cap.bin", []byte{0xa1, 0xb2, 0xc3, 0xd4, 0x00}, "pcaps", "magic"},   // pcap magic
		{"img.e01", ewf, "disk_images", "magic"},                              // EWF magic (seg 1)
		{"vm.kdmv", []byte("KDMV____"), "VM_files", "magic"},                  // VMDK sparse magic
		{"log.evtx", []byte("ElfFile\x00"), "logs/winevt", "ext"},             // evtx by ext
		{"dump.mem", []byte("no magic here"), "memory", "ext"},                // memory by ext
		{"disk.e01x", []byte("no magic"), "", "unknown"},                      // .e01x: no magic, no ext claim
		{"raw.raw", []byte("headerless"), "", "ambiguous:disk_images,memory"}, // .raw: disk (ext) + memory (ext)
		{"notes.txt", []byte("hello"), "", "unknown"},                         // nothing recognises it
	}
	for _, c := range cases {
		sub, by := Classify(mk(c.file, c.data))
		if sub != c.wantSubdir || by != c.wantBy {
			t.Errorf("Classify(%s) = (%q, %q), want (%q, %q)", c.file, sub, by, c.wantSubdir, c.wantBy)
		}
	}
}

// The exported detectors are the reuse surface for the lanes, so pin them
// directly (a lane that walks its own inputs calls these, not Classify).
func TestIsPcap(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if !IsPcap(mk("x.bin", []byte{0xa1, 0xb2, 0xc3, 0xd4, 0x00})) {
		t.Error("pcap magic not recognised")
	}
	if !IsPcap(mk("y.pcapng", []byte("no magic"))) {
		t.Error("pcap by extension not recognised")
	}
	if IsPcap(mk("z.txt", []byte("hello"))) {
		t.Error("plain file wrongly typed as pcap")
	}
}

func TestDetectFormat(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ewf := append([]byte{0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00, 0x00}, []byte{0x01, 0x00}...)
	if got := DetectFormat(mk("a", ewf)); got != "ewf1" {
		t.Errorf("EWF seg-1 = %q, want ewf1", got)
	}
	if got := DetectFormat(mk("b", []byte("KDMV____"))); got != "vmdk" {
		t.Errorf("KDMV = %q, want vmdk", got)
	}
	if got := DetectFormat(mk("c", []byte("nothing"))); got != "" {
		t.Errorf("no signature = %q, want empty", got)
	}
}

func TestExtFormat(t *testing.T) {
	cases := map[string]string{
		"disk.E01":     "ewf1",
		"disk.e02":     "ewf-cont",
		"vm-flat.vmdk": "vmdk-extent",
		"vm.vmdk":      "vmdk",
		"image.raw":    "raw",
		"nothing.txt":  "",
	}
	for name, want := range cases {
		if got := ExtFormat(name); got != want {
			t.Errorf("ExtFormat(%s) = %q, want %q", name, got, want)
		}
	}
}
