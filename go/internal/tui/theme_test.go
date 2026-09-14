package tui

import (
	"testing"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"

	"github.com/get-sybers/dx_dfir/go/internal/model"
)

func TestFrameModeSelection(t *testing.T) {
	cases := map[string]ui.Color{
		"ember":     ui.Color(94),
		"dusk":      ui.Color(130),
		"driftwood": ui.Color(137),
		"EMBER":     ui.Color(94), // case-insensitive
		"":          ui.Color(94), // unset → default
		"nonsense":  ui.Color(94), // unknown → default
	}
	for env, want := range cases {
		t.Setenv("DXDFIR_THEME", env)
		initTheme()
		if colBorder != want {
			t.Errorf("DXDFIR_THEME=%q: colBorder = %d, want %d", env, colBorder, want)
		}
		// The frame border is the non-text chrome that must not be near-white.
		if ui.Theme.Block.Border.Fg != colBorder {
			t.Errorf("DXDFIR_THEME=%q: Theme border not applied", env)
		}
	}
}

func TestInitThemeNoNearWhiteChrome(t *testing.T) {
	t.Setenv("DXDFIR_THEME", "ember")
	initTheme()
	// Non-text chrome must be warm, never the ANSI-white / near-white indices.
	nearWhite := map[ui.Color]bool{7: true, 15: true, 231: true, 255: true, 253: true, 230: true}
	for name, c := range map[string]ui.Color{
		"border":       ui.Theme.Block.Border.Fg,
		"inactive tab": ui.Theme.Tab.Inactive.Fg,
		"gauge bar":    ui.Theme.Gauge.Bar,
	} {
		if nearWhite[c] {
			t.Errorf("%s is near-white (%d) — non-text chrome must be warm", name, c)
		}
	}
	// Titles are text, so cream is allowed and expected.
	if ui.Theme.Block.Title.Fg != colTitle {
		t.Errorf("title should be cream %d, got %d", colTitle, ui.Theme.Block.Title.Fg)
	}
}

// TestPipelineGaugeBarColor guards the progress-gauge state keying: it must not
// turn "done" green when Lanes is empty (a job that reports Overall.Pct but no
// lanes, e.g. collection hashing) — it should read running until it truly settles.
func TestPipelineGaugeBarColor(t *testing.T) {
	build := func(snap *model.Snapshot) ui.Color {
		v := &shellView{gauge: widgets.NewGauge(), snap: snap}
		v.buildGauge()
		return v.gauge.BarColor
	}
	cases := []struct {
		name string
		snap *model.Snapshot
		want ui.Color
	}{
		{"empty lanes stays running", &model.Snapshot{Overall: model.Overall{Pct: 50}}, colBlue},
		{"running lanes", &model.Snapshot{Lanes: []model.Lane{{State: model.Running}, {State: model.Queued}}}, colBlue},
		{"all settled → done", &model.Snapshot{Lanes: []model.Lane{{State: model.Done}, {State: model.Skipped}}}, colGreen},
		{"any failed → failed", &model.Snapshot{Lanes: []model.Lane{{State: model.Done}, {State: model.Failed}}}, colRed},
	}
	for _, c := range cases {
		if got := build(c.snap); got != c.want {
			t.Errorf("%s: BarColor = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestGaugeLoadRamp(t *testing.T) {
	cases := []struct {
		pct  int
		want ui.Color
	}{
		{0, colBlue}, {59, colBlue}, {60, colYellow}, {84, colYellow}, {85, colCritical}, {100, colCritical},
	}
	for _, c := range cases {
		if got := gaugeLoad(c.pct); got != c.want {
			t.Errorf("gaugeLoad(%d) = %d, want %d", c.pct, got, c.want)
		}
	}
}
