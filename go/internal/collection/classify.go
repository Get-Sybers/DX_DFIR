package collection

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// This file ports the collection classifier (epic #174, phase 4): where a raw
// evidence file sorts to, magic-first, reusing the processors' own detectors —
// pcap magic (zeek), disk-image/VM magic + extension (the plaso module's
// detect_format/ext_format, which are pure header/extension sniffing, NOT the
// log2timeline PROCESSOR, which stays in Docker/Ansible), memory-dump and
// EVTX extensions. Content beats extension, so a mislabelled image is filed by
// its real type.

// pcapMagic mirrors zeek._PCAP_MAGIC (4-byte header hex).
var pcapMagic = map[string]bool{
	"a1b2c3d4": true, "d4c3b2a1": true, "a1b23c4d": true, "4d3cb2a1": true, "0a0d0d0a": true,
}

var pcapExts = []string{".pcap", ".pcapng", ".cap"}

// memoryExts mirrors volatility._MEMORY_EXTS (plus the "*dramimage" suffix).
var memoryExts = []string{".raw", ".mem", ".dmp", ".lime", ".vmem", ".bin", ".dump", ".vmsn", ".crash"}

// diskFormats / vmFormats mirror _DISK_FORMATS / _VM_FORMATS.
var diskFormats = map[string]bool{"ewf1": true, "ewf2": true, "ewf-cont": true, "qcow2": true, "aff": true, "raw": true}
var vmFormats = map[string]bool{"vmdk": true, "vmdk-extent": true, "vhd": true, "vhdx": true}

var vmdkExtentRe = regexp.MustCompile(`-flat\.vmdk$|-delta\.vmdk$|-s[0-9]+\.vmdk$`)

// headHex reads the first n bytes of a file and returns them lower-hex.
func headHex(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, n)
	m, _ := f.Read(buf)
	return hexLower(buf[:m])
}

func hexLower(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[2*i] = hexdigits[c>>4]
		out[2*i+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// isPcap mirrors zeek.is_pcap: content magic first, extension fallback.
func isPcap(path string) bool {
	if pcapMagic[headHex(path, 4)] {
		return true
	}
	low := strings.ToLower(path)
	for _, e := range pcapExts {
		if strings.HasSuffix(low, e) {
			return true
		}
	}
	return false
}

// isMemoryImage mirrors volatility.is_memory_image (extension-based).
func isMemoryImage(name string) bool {
	low := strings.ToLower(name)
	for _, e := range memoryExts {
		if strings.HasSuffix(low, e) {
			return true
		}
	}
	return strings.HasSuffix(low, "dramimage")
}

// detectFormat mirrors plaso.detect_format: identify a disk-image/VM file by
// content (a few header bytes + a VHD footer) → ewf1|ewf-cont|ewf2|vmdk|qcow2|
// vhdx|vhd, "" when no signature matches.
func detectFormat(path string) string {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return ""
	}
	h := headHex(path, 8)
	switch {
	case h == "455646090d0aff00": // EWF "EVF\x09\x0d\x0a\xff\x00"
		// segment number: uint16 LE at offset 9; only segment 1 heads the set.
		segno := 0
		if f, e := os.Open(path); e == nil {
			seg := make([]byte, 2)
			if _, e := f.ReadAt(seg, 9); e == nil {
				segno = int(seg[0]) | int(seg[1])<<8
			}
			f.Close()
		}
		if segno == 1 {
			return "ewf1"
		}
		return "ewf-cont"
	case h == "455646320d0a8100": // EWF2
		return "ewf2"
	case strings.HasPrefix(h, "4b444d56"): // "KDMV" monolithic sparse VMDK
		return "vmdk"
	case strings.HasPrefix(h, "514649fb"): // "QFI\xfb"
		return "qcow2"
	case h == "7668647866696c65": // "vhdxfile"
		return "vhdx"
	case h == "636f6e6563746978": // "conectix" (dynamic VHD header)
		return "vhd"
	}
	// VMDK text descriptor.
	if f, e := os.Open(path); e == nil {
		d := make([]byte, 64)
		n, _ := f.Read(d)
		f.Close()
		if strings.HasPrefix(string(d[:n]), "# Disk DescriptorFile") {
			return "vmdk"
		}
	}
	// A fixed-format VHD carries "conectix" only in its 512-byte footer.
	if fi.Size() >= 512 {
		if f, e := os.Open(path); e == nil {
			foot := make([]byte, 8)
			if _, e := f.ReadAt(foot, fi.Size()-512); e == nil && hexLower(foot) == "636f6e6563746978" {
				f.Close()
				return "vhd"
			}
			f.Close()
		}
	}
	return ""
}

// extFormat mirrors plaso.ext_format: the format implied by the file name.
func extFormat(name string) string {
	n := strings.ToLower(filepath.Base(name))
	switch {
	case vmdkExtentRe.MatchString(n):
		return "vmdk-extent"
	case strings.HasSuffix(n, ".e01"):
		return "ewf1"
	case regexp.MustCompile(`\.e[0-9][0-9]$`).MatchString(n):
		return "ewf-cont"
	case strings.HasSuffix(n, ".vmdk"):
		return "vmdk"
	case strings.HasSuffix(n, ".vhd"):
		return "vhd"
	case strings.HasSuffix(n, ".vhdx"):
		return "vhdx"
	case strings.HasSuffix(n, ".aff"):
		return "aff"
	case strings.HasSuffix(n, ".raw"), strings.HasSuffix(n, ".img"), strings.HasSuffix(n, ".dd"):
		return "raw"
	}
	return ""
}

// contentSubdir mirrors _content_subdir: the lane subdir from magic bytes alone.
func contentSubdir(path string) string {
	if pcapMagic[headHex(path, 4)] {
		return "pcaps"
	}
	switch f := detectFormat(path); {
	case diskFormats[f]:
		return "disk_images"
	case vmFormats[f]:
		return "VM_files"
	}
	return ""
}

// extSubdirs mirrors _ext_subdirs: the lane subdirs claiming a file by name.
func extSubdirs(path string) map[string]bool {
	claims := map[string]bool{}
	if isPcap(path) {
		claims["pcaps"] = true
	}
	switch f := extFormat(path); {
	case diskFormats[f]:
		claims["disk_images"] = true
	case vmFormats[f]:
		claims["VM_files"] = true
	}
	if isMemoryImage(filepath.Base(path)) {
		claims["memory"] = true
	}
	if strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".evtx") {
		claims["logs/winevt"] = true
	}
	return claims
}

// Classify mirrors classify(): (subdir, detectedBy). subdir is "" for
// ambiguous/unknown. detectedBy is "magic" | "ext" | "ambiguous:a,b" | "unknown".
func Classify(path string) (subdir, detectedBy string) {
	if magic := contentSubdir(path); magic != "" {
		return magic, "magic"
	}
	claims := extSubdirs(path)
	if len(claims) == 0 {
		return "", "unknown"
	}
	if len(claims) > 1 {
		keys := make([]string, 0, len(claims))
		for k := range claims {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "", "ambiguous:" + strings.Join(keys, ",")
	}
	for k := range claims {
		return k, "ext"
	}
	return "", "unknown"
}
