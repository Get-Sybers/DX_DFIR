//go:build linux

package plain

import (
	"os"
	"syscall"
	"unsafe"
)

// termCols returns the terminal width of f via the TIOCGWINSZ ioctl, or 80 when
// f is not a terminal or the call fails. Dependency-free (no x/sys, no x/term)
// so the front-end keeps its small, pinned module set.
func termCols(f *os.File) int {
	type winsize struct {
		rows, cols, xpix, ypix uint16
	}
	var ws winsize
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 || ws.cols == 0 {
		return 80
	}
	return int(ws.cols)
}
