package identify

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFixture stages a minimal evidence-taxonomy/ and returns its dir. It mirrors
// the real schema (index + one YAML per lane) so the loader, the generic offset
// matcher, the wildcard handling and the special probes are all exercised.
func writeFixture(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence-taxonomy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"_index.yml": "catch_all_subdir: other_raw_data\n" +
			"order: [pcaps, logs_winevt, disk_images, vm_files, memory, filesystem_documents, other_raw_data_sql, mobile]\n",
		"pcaps.yml": "name: pcaps\nsubdir: pcaps\next: [.pcap, .pcapng]\n" +
			"signatures:\n  - {hex: \"A1 B2 C3 D4\", offset: 0}\n",
		"logs_winevt.yml": "name: logs_winevt\nsubdir: logs/winevt\next: [.evtx]\n" +
			"signatures:\n  - {hex: \"45 6C 66 46 69 6C 65 00\", offset: 0}\n",
		"disk_images.yml": "name: disk_images\nsubdir: disk_images\next: [.e01, .raw, .dd]\n" +
			"signatures:\n  - {hex: \"45 56 46 09 0D 0A FF 00\", offset: 0}\n",
		"vm_files.yml": "name: vm_files\nsubdir: VM_files\nset_marker: [.vmx]\next: [.vmdk]\n" +
			"signatures:\n" +
			"  - {hex: \"4B 44 4D 56\", offset: 0}\n" +
			"  - {hex: \"23 20 44 69 73 6B 20 44 65 73 63 72 69 70 74 6F 72 46 69 6C 65\", offset: 0, kind: \"special:vmdk-descriptor\"}\n",
		"memory.yml": "name: memory\nsubdir: memory\next: [.mem, .dmp]\n" +
			"signatures:\n  - {hex: \"4D 44 4D 50\", offset: 0}\n",
		"filesystem_documents.yml": "name: filesystem_documents\nsubdir: filesystem/documents\next: [.pdf, .docx]\n" +
			"signatures:\n" +
			"  - {hex: \"25 50 44 46\", offset: 0}\n" +
			"  - {hex: \"FF D8 FF E0 nn nn 4A 46 49 46 00 01\", offset: 0}\n" +
			"  - {hex: \"50 4B 03 04\", offset: 0, kind: \"special:ooxml\"}\n",
		"other_raw_data_sql.yml": "name: other_raw_data_sql\nsubdir: other_raw_data/sql\next: [.sqlite, .db]\n" +
			"signatures:\n  - {hex: \"53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00\", offset: 0}\n",
		"mobile.yml": "name: mobile\nsubdir: mobile\nset_marker: [.ufd, .ufdr]\next: [.ufd, .ufdr, .tar]\n" +
			"signatures:\n  - {hex: \"50 4B 03 04\", offset: 0, kind: \"special:apk\"}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mk(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClassify(t *testing.T) {
	tax, err := LoadFromDir(writeFixture(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	jfif := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}
	cases := []struct {
		file       string
		data       []byte
		wantSubdir string
		wantBy     string
	}{
		{"cap.bin", []byte{0xA1, 0xB2, 0xC3, 0xD4, 0x00}, "pcaps", "magic"},         // pcap magic beats .bin
		{"log.evtx", []byte("ElfFile\x00rest"), "logs/winevt", "magic"},             // evtx magic
		{"img.e01", []byte("EVF\x09\x0d\x0a\xff\x00xx"), "disk_images", "magic"},    // EWF magic
		{"vm.dat", []byte("KDMV____"), "VM_files", "magic"},                         // VMDK sparse magic
		{"crash.001", []byte("MDMP____"), "memory", "magic"},                        // minidump magic
		{"report.out", []byte("%PDF-1.7"), "filesystem/documents", "magic"},         // pdf magic
		{"photo.dat", jfif, "filesystem/documents", "magic"},                        // JFIF via nn wildcards
		{"store.dat", []byte("SQLite format 3\x00"), "other_raw_data/sql", "magic"}, // sqlite magic
		{"dump.mem", []byte("no magic here"), "memory", "ext"},                      // memory by ext
		{"disk.raw", []byte("headerless"), "disk_images", "ext"},                    // .raw by ext (precedence)
		{"notes.txt", []byte("hello"), "other_raw_data", "catch-all"},               // nothing claims it
	}
	for _, c := range cases {
		sub, by := tax.Classify(mk(t, c.file, c.data))
		if sub != c.wantSubdir || by != c.wantBy {
			t.Errorf("Classify(%s) = (%q, %q), want (%q, %q)", c.file, sub, by, c.wantSubdir, c.wantBy)
		}
	}
}

func TestSpecialDetectors(t *testing.T) {
	tax, err := LoadFromDir(writeFixture(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// VMDK text descriptor -> VM_files by the special probe (no KDMV magic).
	if sub, by := tax.Classify(mk(t, "desc.dat", []byte("# Disk DescriptorFile\nversion=1"))); sub != "VM_files" || by != "magic" {
		t.Errorf("vmdk descriptor = (%q,%q), want (VM_files, magic)", sub, by)
	}
	// OOXML: a ZIP that contains [Content_Types].xml -> documents; a bare ZIP does not.
	ooxml := append([]byte{0x50, 0x4B, 0x03, 0x04}, []byte("....[Content_Types].xml....")...)
	if sub, _ := tax.Classify(mk(t, "doc.dat", ooxml)); sub != "filesystem/documents" {
		t.Errorf("ooxml zip = %q, want filesystem/documents", sub)
	}
	bareZip := append([]byte{0x50, 0x4B, 0x03, 0x04}, []byte("just a zip of stuff")...)
	if sub, by := tax.Classify(mk(t, "arc.dat", bareZip)); sub != "other_raw_data" || by != "catch-all" {
		t.Errorf("bare zip = (%q,%q), want (other_raw_data, catch-all)", sub, by)
	}
}

func TestArchiveProbesAndISO(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence-taxonomy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"_index.yml": "catch_all_subdir: other_raw_data\n" +
			"order: [disk_images, filesystem_documents, mobile]\n",
		"disk_images.yml": "name: disk_images\nsubdir: disk_images\next: [.iso]\nsignatures:\n" +
			"  - {hex: \"43 44 30 30 31\", offset: 32769}\n" +
			"  - {hex: \"6B 6F 6C 79\", offset: -512, kind: \"special:dmg-footer\"}\n",
		"filesystem_documents.yml": "name: filesystem_documents\nsubdir: filesystem/documents\next: []\nsignatures:\n" +
			"  - {hex: \"50 4B 03 04\", offset: 0, kind: \"special:ooxml\"}\n" +
			"  - {hex: \"50 4B 03 04\", offset: 0, kind: \"special:odf\"}\n",
		"mobile.yml": "name: mobile\nsubdir: mobile\next: []\nsignatures:\n" +
			"  - {hex: \"50 4B 03 04\", offset: 0, kind: \"special:apk\"}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tax, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// ISO 9660: "CD001" at 0x8001 (32769).
	iso := make([]byte, 32769+5)
	copy(iso[32769:], []byte("CD001"))
	// DMG: "koly" trailer in the last 512 bytes.
	dmg := make([]byte, 1024)
	copy(dmg[1024-512:], []byte("koly"))
	zip := func(member string) []byte {
		return append([]byte{0x50, 0x4B, 0x03, 0x04}, []byte("......"+member+"......")...)
	}
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"cd.iso", iso, "disk_images"},
		{"disk.bin", dmg, "disk_images"},                                                          // DMG footer, extension-blind
		{"report.zip", zip("[Content_Types].xml"), "filesystem/documents"},                        // OOXML
		{"sheet.zip", zip("mimetype vnd.oasis.opendocument.spreadsheet"), "filesystem/documents"}, // ODF
		{"app.zip", zip("AndroidManifest.xml"), "mobile"},                                         // APK
		{"plain.zip", zip("just files here"), "other_raw_data"},                                   // bare archive -> catch-all
	}
	for _, c := range cases {
		if sub, _ := tax.Classify(mk(t, c.name, c.data)); sub != c.want {
			t.Errorf("Classify(%s) = %q, want %q", c.name, sub, c.want)
		}
	}
}

func TestVHDFooter(t *testing.T) {
	// A fixed-format VHD carries "conectix" only in the last 512 bytes.
	buf := make([]byte, 1024)
	copy(buf[512:], []byte("conectix"))
	if !isVHDFooter(mk(t, "fixed.dat", buf)) {
		t.Error("VHD footer not detected")
	}
	if isVHDFooter(mk(t, "small.dat", []byte("too small"))) {
		t.Error("VHD footer false positive on a tiny file")
	}
}

func TestSetLaneForDir(t *testing.T) {
	tax, err := LoadFromDir(writeFixture(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// A directory holding a .vmx is one VM export set.
	dir := t.TempDir()
	for _, f := range []string{"disk.vmdk", "disk-flat.vmdk", "machine.vmx"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if lane := tax.SetLaneForDir(dir); lane == nil || lane.Subdir != "VM_files" {
		t.Errorf("SetLaneForDir = %v, want VM_files lane", lane)
	}
	// A directory holding a UFED/Cellebrite report (.ufdr) is one mobile
	// extraction set — moved whole, never split across lanes by its parts.
	mob := t.TempDir()
	for _, f := range []string{"extraction.ufdr", "files.tar", "report.pdf"} {
		if err := os.WriteFile(filepath.Join(mob, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if lane := tax.SetLaneForDir(mob); lane == nil || lane.Subdir != "mobile" {
		t.Errorf("SetLaneForDir(mobile) = %v, want mobile lane", lane)
	}
	// A plain directory is not a set.
	plain := t.TempDir()
	_ = os.WriteFile(filepath.Join(plain, "a.pcap"), []byte("x"), 0o644)
	if lane := tax.SetLaneForDir(plain); lane != nil {
		t.Errorf("SetLaneForDir(plain) = %v, want nil", lane)
	}
}
