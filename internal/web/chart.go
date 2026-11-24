package web

import (
	"sort"

	"github.com/chrobson/ramparteye/internal/model"
)

// Geometry of the inline SVG bar charts (user units of the viewBox).
const (
	chartWidth    = 320
	chartRowH     = 22
	chartLabelW   = 104
	chartBarMaxW  = 160
	chartBarH     = 10
	chartMaxRows  = 8
	chartCountGap = 8
)

// BarChart is a horizontal bar chart rendered as inline SVG by the
// "bar-chart" template. Labels reach the page only through template
// escaping.
type BarChart struct {
	Rows          []Bar
	Width, Height int
	LabelW        int // x where bars start
	CountX        int // x of the count text
}

// Bar is one row of a BarChart.
type Bar struct {
	Label string
	Count int
	Y     int // top of the row
	W     int // bar width, at least 2 for a non-zero count
	Class string
}

func newBarChart(rows []Bar) BarChart {
	c := BarChart{Width: chartWidth, Height: len(rows) * chartRowH, LabelW: chartLabelW}
	maxCount := 0
	for _, r := range rows {
		maxCount = max(maxCount, r.Count)
	}
	for i := range rows {
		rows[i].Y = i * chartRowH
		if rows[i].Count > 0 {
			rows[i].W = max(2, rows[i].Count*chartBarMaxW/maxCount)
		}
		if rows[i].Class == "" {
			rows[i].Class = "fill-muted"
		}
	}
	c.Rows = rows
	c.CountX = chartLabelW + chartBarMaxW + chartCountGap
	return c
}

// categoryChart charts detections per category, most first.
func categoryChart(counts map[string]int) BarChart {
	var rows []Bar
	for k, n := range counts {
		rows = append(rows, Bar{Label: k, Count: n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Label < rows[j].Label
	})
	if len(rows) > chartMaxRows {
		rows = rows[:chartMaxRows]
	}
	return newBarChart(rows)
}

var hostStateOrder = []struct {
	kind  model.HostStateKind
	class string
}{
	{model.HostUp, "fill-ok"},
	{model.HostUnstable, "fill-med"},
	{model.HostDown, "fill-bad"},
	{model.HostInactive, "fill-dim"},
}

// hostStateChart charts the hosts per lifecycle state (zero states stay
// out).
func hostStateChart(counts map[model.HostStateKind]int) BarChart {
	var rows []Bar
	for _, s := range hostStateOrder {
		if n := counts[s.kind]; n > 0 {
			rows = append(rows, Bar{Label: string(s.kind), Count: n, Class: s.class})
		}
	}
	return newBarChart(rows)
}
