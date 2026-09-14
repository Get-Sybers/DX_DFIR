// Package fsx holds the small filesystem predicates and operations shared across
// the dxdfir packages — one home for helpers that were otherwise re-implemented
// per package (isDir was copy-pasted verbatim in collection, health and repo).
// Thin wrappers over os with the exact error-swallowing semantics the callers
// rely on: a predicate is false when the path can't be stat'd, never an error.
package fsx

import (
	"io"
	"os"
)

// IsDir reports whether p exists and is a directory.
func IsDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// IsRegularFile reports whether p exists and is a regular file.
func IsRegularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// IsSymlink reports whether p is a symlink (the link itself, not its target).
func IsSymlink(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

// Exists reports whether p exists, counting a symlink itself (even a dangling
// one) — it uses Lstat, so it never follows the link.
func Exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// Move renames src→dst, falling back to copy+remove when the two are on
// different filesystems (os.Rename fails across devices — e.g. a tmpfs staging
// dir to a data volume).
func Move(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		in.Close()
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		in.Close()
		out.Close()
		return err
	}
	in.Close()
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}
