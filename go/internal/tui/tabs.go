package tui

import (
	"image"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

// sunsetTabs is widgets.TabPane with the one detail the theme cannot reach fixed:
// termui hardcodes the inter-tab separator to ANSI-white (tabs.go VERTICAL_LINE),
// which violates the Sunset rule that no NON-TEXT chrome is near-white. Draw is a
// verbatim copy of widgets.TabPane.Draw with that single separator cell re-emitted
// in the frame's warm border tone instead of white. Everything else (tab labels,
// active/inactive styles, block frame) still comes from ui.Theme.
type sunsetTabs struct {
	*widgets.TabPane
}

// newSunsetTabs builds the wrapper; the embedded TabPane copies Theme.Tab.* at
// construction, so initTheme must have run first.
func newSunsetTabs(names ...string) *sunsetTabs {
	return &sunsetTabs{TabPane: widgets.NewTabPane(names...)}
}

// Draw mirrors widgets.TabPane.Draw exactly, except the separator uses colBorder.
func (t *sunsetTabs) Draw(buf *ui.Buffer) {
	t.Block.Draw(buf)

	x := t.Inner.Min.X
	for i, name := range t.TabNames {
		style := t.InactiveTabStyle
		if i == t.ActiveTabIndex {
			style = t.ActiveTabStyle
		}
		buf.SetString(
			ui.TrimString(name, t.Inner.Max.X-x),
			style,
			image.Pt(x, t.Inner.Min.Y),
		)

		x += 1 + len(name)

		if i < len(t.TabNames)-1 && x < t.Inner.Max.X {
			buf.SetCell(
				ui.NewCell(ui.VERTICAL_LINE, styleFg(colBorder)), // was ANSI-white
				image.Pt(x, t.Inner.Min.Y),
			)
		}

		x += 2
	}
}
