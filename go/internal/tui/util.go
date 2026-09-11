package tui

import (
	"fmt"
	"time"
)

func humanElapsed(start time.Time) string {
	if start.IsZero() {
		return "00:00:00"
	}
	return fmtDur(time.Since(start))
}

// fmtDur formats a duration as hh:mm:ss.
func fmtDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", s/3600, (s%3600)/60, s%60)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

var spinnerFrames = []string{"-", "\\", "|", "/"}

// spinnerFrame advances at ~2 Hz off the wall clock (redraws are ticker-driven,
// so this animates without a dedicated goroutine).
func spinnerFrame() string {
	return spinnerFrames[(time.Now().UnixNano()/int64(500*time.Millisecond))%int64(len(spinnerFrames))]
}
