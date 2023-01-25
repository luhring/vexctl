package table

import (
	"errors"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/openvex/vexctl/pkg/formats"
)

const (
	widthPackage       = 28
	widthVersion       = 24
	widthType          = 12
	widthVulnerability = 20
	widthSeverity      = 12
)

const (
	hexNotSelected = "#777777"
	hexSelected    = "#FFFFFF"
)

const notFound = -1

var NoMatchFound = errors.New("no row matched expression")

var (
	styleHeaderRow          = lipgloss.NewStyle().Foreground(lipgloss.Color(hexNotSelected)).Bold(true)
	styleDataRowNotSelected = lipgloss.NewStyle().Foreground(lipgloss.Color(hexNotSelected))
	styleDataRowSelected    = lipgloss.NewStyle().Foreground(lipgloss.Color(hexSelected))
)

type Model struct {
	windowStart    int
	windowSize     int
	rowSelected    int
	findExpression string

	data formats.Normalized
}

func New(data formats.Normalized) Model {
	return Model{
		windowStart: 0,
		windowSize:  10,
		rowSelected: 0,
		data:        data,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {

	// Is it a key press?
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}

		switch msg.String() {

		case "q":
			return m, tea.Quit

		case "up", "k":
			return m.moveUp(), nil

		case "down", "j":
			return m.moveDown(), nil

		case "g":
			return m.jumpToStart(), nil

		case "G":
			return m.jumpToEnd(), nil

		case "w":
			return m.pageUp(), nil

		case "z":
			return m.pageDown(), nil

		}
	}

	return m, nil
}

func (m Model) View() string {
	output := ""
	output += renderHeaderRow()
	output += m.renderRowsWindow(m.windowStart, m.windowSize)

	return output
}

func (m Model) SetHeight(h int) Model {
	m.windowSize = h - 2
	return m
}

func (m Model) Find(expr string) (Model, error) {
	m.findExpression = expr
	foundIndex := m.find(expr)
	if foundIndex == notFound {
		return Model{}, NoMatchFound
	}

	m = m.selectAndShowRow(foundIndex)
	return m, nil
}

func (m Model) FindNext() (Model, error) {
	foundIndex := m.findNext(m.findExpression)
	if foundIndex == notFound {
		return Model{}, NoMatchFound
	}

	m = m.selectAndShowRow(foundIndex)
	return m, nil
}

func (m Model) FindPrevious() (Model, error) {
	foundIndex := m.findPrevious(m.findExpression)
	if foundIndex == notFound {
		return Model{}, NoMatchFound
	}

	m = m.selectAndShowRow(foundIndex)
	return m, nil
}

func (m Model) find(expr string) int {
	for i, match := range m.data.Matches {
		if filterMatchFound(match, expr) {
			return i
		}
	}

	return notFound
}

func (m Model) findNext(expr string) int {
	i := m.rowSelected

	for {
		i++
		if i > m.lastRowIndex() {
			i = 0
		}
		if i == m.rowSelected {
			return notFound
		}

		match := m.data.Matches[i]
		if filterMatchFound(match, expr) {
			return i
		}
	}
}

func (m Model) findPrevious(expr string) int {
	i := m.rowSelected

	for {
		i--
		if i < 0 {
			i = m.lastRowIndex()
		}
		if i == m.rowSelected {
			return notFound
		}

		match := m.data.Matches[i]
		if filterMatchFound(match, expr) {
			return i
		}
	}
}

func filterMatchFound(match formats.Match, expr string) bool {
	return strings.Contains(match.Package.Name, expr) || strings.Contains(match.Vulnerability.ID, expr)
}

// selectAndShowRow updates the index setting for the "selected row" and then
// updates the table window appropriately to ensure the selected row is shown.
func (m Model) selectAndShowRow(i int) Model {
	m.rowSelected = i
	m = m.updateWindow()
	return m
}

func (m Model) totalRowCount() int {
	return len(m.data.Matches)
}

func (m Model) lastRowIndex() int {
	return m.totalRowCount() - 1
}

func (m Model) dataWindowEnd() int {
	return m.windowStart + m.windowSize - 1
}

func (m Model) renderRowsWindow(start, size int) string {
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

		isSelected := i == m.rowSelected

		output += renderDataRow(m.data.Matches[i], isSelected)
	}

	return output
}

func renderHeaderRow() string {
	unstyled := "  " +
		renderCell("Package", widthPackage) +
		renderCell("Version", widthVersion) +
		renderCell("Type", widthType) +
		renderCell("Vulnerability", widthVulnerability) +
		renderCell("Severity", widthSeverity)

	return styleHeaderRow.Render(unstyled) + "\n"
}

func renderDataRow(m formats.Match, isSelected bool) string {
	row := renderCell(m.Package.Name, widthPackage) +
		renderCell(m.Package.Version, widthVersion) +
		renderCell(m.Package.Type, widthType) +
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

func (m Model) moveUp() Model {
	if m.rowSelected == 0 {
		return m
	}

	m = m.selectAndShowRow(m.rowSelected - 1)
	return m
}

func (m Model) moveDown() Model {
	if m.rowSelected == m.lastRowIndex() {
		return m
	}

	m = m.selectAndShowRow(m.rowSelected + 1)
	return m
}

func (m Model) jumpToStart() Model {
	m = m.selectAndShowRow(0)
	return m
}

func (m Model) jumpToEnd() Model {
	m = m.selectAndShowRow(m.lastRowIndex())
	return m
}

func (m Model) pageUp() Model {
	if m.rowSelected > m.windowStart {
		m.rowSelected = m.windowStart
		return m
	}

	// already at the top of the window

	newSelectedRow := m.rowSelected - m.windowSize
	if newSelectedRow < 0 {
		// catch out-of-bounds case
		newSelectedRow = 0
	}

	m = m.selectAndShowRow(newSelectedRow)

	return m
}

func (m Model) pageDown() Model {
	if windowEnd := m.dataWindowEnd(); m.rowSelected < windowEnd {
		if windowEnd > m.lastRowIndex() {
			m.rowSelected = m.lastRowIndex()
			return m
		}

		m.rowSelected = windowEnd
		return m
	}

	// already at the bottom of the window

	newSelectedRow := m.rowSelected + m.windowSize
	if lastRow := m.lastRowIndex(); newSelectedRow > lastRow {
		// catch out-of-bounds case
		newSelectedRow = lastRow
	}

	m = m.selectAndShowRow(newSelectedRow)

	return m
}

func (m Model) updateWindow() Model {
	newSelectedIndex := m.rowSelected

	windowFirst := m.windowStart
	windowLast := m.dataWindowEnd()

	if newSelectedIndex >= windowFirst && newSelectedIndex <= windowLast {
		// selection already appears in window
		return m
	}

	if newSelectedIndex < windowFirst {
		// jump window backward to start at selection
		m.windowStart = newSelectedIndex
		return m
	}

	if newSelectedIndex > windowLast {
		// jump window forward so that windowLast is selection
		newStart := newSelectedIndex - (m.windowSize - 1)
		m.windowStart = newStart
		return m
	}

	return m
}
