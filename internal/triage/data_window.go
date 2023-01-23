package triage

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/openvex/vexctl/pkg/formats"
)

const (
	widthPackage       = 28
	widthVersion       = 22
	widthVulnerability = 20
	widthSeverity      = 12
)

const (
	hexNotSelected = "#777777"
	hexSelected    = "#FFFFFF"
)

var (
	styleHeaderRow          = lipgloss.NewStyle().Foreground(lipgloss.Color(hexNotSelected)).Bold(true)
	styleDataRowNotSelected = lipgloss.NewStyle().Foreground(lipgloss.Color(hexNotSelected))
	styleDataRowSelected    = lipgloss.NewStyle().Foreground(lipgloss.Color(hexSelected))
)

func (m model) totalRowCount() int {
	return len(m.data.Matches)
}

func (m model) lastRowIndex() int {
	return m.totalRowCount() - 1
}

func (m model) dataWindowEnd() int {
	return m.dataWindowStart + m.dataWindowSize - 1
}

func (m model) renderRowsWindow(start, size int) string {
	lastRow := m.lastRowIndex()

	if start > lastRow {
		return "\n"
	}

	output := ""

	for i := start; i < start+size; i++ {
		if i > lastRow {
			output += "\n"
			continue
		}

		isSelected := i == m.dataRowSelected

		output += renderDataRow(m.data.Matches[i], isSelected)
	}

	return output
}

func renderHeaderRow() string {
	unstyled := "  " +
		renderCell("Package", widthPackage) +
		renderCell("Version", widthVersion) +
		renderCell("Vulnerability", widthVulnerability) +
		renderCell("Severity", widthSeverity)

	return styleHeaderRow.Render(unstyled) + "\n"
}

func renderDataRow(m formats.Match, isSelected bool) string {
	row := renderCell(m.Package.Name, widthPackage) +
		renderCell(m.Package.Version, widthVersion) +
		renderCell(m.Vulnerability.ID, widthVulnerability) +
		renderCell(m.Vulnerability.Severity, widthSeverity)

	if isSelected {
		row = "> " + row
	} else {
		row = "  " + row
		row = styleDataRowNotSelected.Render(row)
	}

	row += "\n"

	return row
}

func renderCell(content string, size int) string {
	padSize := size - lipgloss.Width(content)

	return lipgloss.NewStyle().PaddingRight(padSize).Render(content)
}

func moveUp(m model) model {
	if m.dataRowSelected == 0 {
		return m
	}

	m.dataRowSelected--
	m = updateWindow(m)
	return m
}

func moveDown(m model) model {
	if m.dataRowSelected == m.lastRowIndex() {
		return m
	}

	m.dataRowSelected++
	m = updateWindow(m)
	return m
}

func jumpToStart(m model) model {
	m.dataRowSelected = 0
	m = updateWindow(m)
	return m
}

func jumpToEnd(m model) model {
	m.dataRowSelected = m.lastRowIndex()
	m = updateWindow(m)
	return m
}

func pageUp(m model) model {
	if m.dataRowSelected > m.dataWindowStart {
		m.dataRowSelected = m.dataWindowStart
		return m
	}

	// already at the top of the window

	newSelectedRow := m.dataRowSelected - m.dataWindowSize
	if newSelectedRow < 0 {
		// catch out-of-bounds case
		newSelectedRow = 0
	}

	m.dataRowSelected = newSelectedRow
	m = updateWindow(m)

	return m
}

func pageDown(m model) model {
	if windowEnd := m.dataWindowEnd(); m.dataRowSelected < windowEnd {
		if windowEnd > m.lastRowIndex() {
			m.dataRowSelected = m.lastRowIndex()
			return m
		}

		m.dataRowSelected = windowEnd
		return m
	}

	// already at the bottom of the window

	newSelectedRow := m.dataRowSelected + m.dataWindowSize
	if lastRow := m.lastRowIndex(); newSelectedRow > lastRow {
		// catch out-of-bounds case
		newSelectedRow = lastRow
	}

	m.dataRowSelected = newSelectedRow
	m = updateWindow(m)

	return m
}

func updateWindow(m model) model {
	newSelectedIndex := m.dataRowSelected

	windowFirst := m.dataWindowStart
	windowLast := m.dataWindowEnd()

	if newSelectedIndex >= windowFirst && newSelectedIndex <= windowLast {
		// selection already appears in window
		return m
	}

	if newSelectedIndex < windowFirst {
		// jump window backward to start at selection
		m.dataWindowStart = newSelectedIndex
		return m
	}

	if newSelectedIndex > windowLast {
		// jump window forward so that windowLast is selection
		newStart := newSelectedIndex - (m.dataWindowSize - 1)
		m.dataWindowStart = newStart
		return m
	}

	return m
}
