//go:build !linux

package plain

import "os"

// termCols falls back to a conservative 80 columns off Linux; the dx front-end
// runs on the Linux host where the ioctl path applies.
func termCols(_ *os.File) int { return 80 }
