package triage

import (
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/openvex/vexctl/pkg/formats"
)

type model struct {
	dataWindowStart, dataWindowSize int
	dataRowSelected                 int

	data formats.Normalized
	mode Mode

	filter textinput.Model
}

type Mode int

const (
	ModeDataScroll Mode = iota
	ModeFilterEntry
)

func NewModel(data formats.Normalized) tea.Model {
	ms := data.Matches

	sort.SliceStable(ms, func(i, j int) bool {
		nameCmp := strings.Compare(ms[i].Package.Name, ms[j].Package.Name)

		if nameCmp != 0 {
			return nameCmp < 0
		}

		vulnCmp := strings.Compare(ms[i].Vulnerability.ID, ms[j].Vulnerability.ID)
		return vulnCmp < 0
	})

	return model{
		dataWindowStart: 0,
		dataWindowSize:  10,
		dataRowSelected: 0,
		data:            data,
		mode:            ModeDataScroll,
		filter:          textinput.Model{},
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {

	// Is it a key press?
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}

		switch m.mode {
		case ModeDataScroll:
			switch msg.String() {

			case "q":
				return m, tea.Quit

			case "up", "k":
				return moveUp(m), nil

			case "down", "j":
				return moveDown(m), nil

			case "g":
				return jumpToStart(m), nil

			case "G":
				return jumpToEnd(m), nil

			case "w":
				return pageUp(m), nil

			case "z":
				return pageDown(m), nil

			case "/":
				m.mode = ModeFilterEntry
				m = updateWindow(m)
				m.filter = newFilterTextInput()
				m.filter.Focus()
				return m, textinput.Blink

			case "n":
				if expr := m.filter.Value(); expr != "" {
					foundIndex := m.findNext(expr)
					if foundIndex >= 0 {
						m.dataRowSelected = foundIndex
						m = updateWindow(m)
						return m, nil
					}

					// TODO: handle not found
				}

			case "N":
				if expr := m.filter.Value(); expr != "" {
					foundIndex := m.findPrevious(expr)
					if foundIndex >= 0 {
						m.dataRowSelected = foundIndex
						m = updateWindow(m)
						return m, nil
					}

					// TODO: handle not found
				}
			}

		case ModeFilterEntry:
			if msg.String() == "enter" {
				expr := m.filter.Value()
				foundIndex := m.find(expr)
				if foundIndex >= 0 {
					m.dataRowSelected = foundIndex
					m = updateWindow(m)
				}
				m.filter.Blur()
				m.mode = ModeDataScroll
				return m, nil
			}

			if msg.String() == "esc" {
				m.filter.Blur()
				m.mode = ModeDataScroll
				return m, nil
			}

			m.filter, cmd = m.filter.Update(msg)
			return m, cmd
		}

	case tea.WindowSizeMsg:
		m.dataWindowSize = msg.Height - lipgloss.Height(renderHeaderRow())
		m = updateWindow(m)
		return m, nil
	}

	m.filter, cmd = m.filter.Update(msg)
	return m, cmd
}

func filterMatchFound(match formats.Match, expr string) bool {
	return strings.Contains(match.Package.Name, expr) || strings.Contains(match.Vulnerability.ID, expr)
}

func (m model) find(expr string) int {
	for i, match := range m.data.Matches {
		if filterMatchFound(match, expr) {
			return i
		}
	}

	return -1
}

func (m model) findNext(expr string) int {
	i := m.dataRowSelected

	for {
		i++
		if i > m.lastRowIndex() {
			i = 0
		}
		if i == m.dataRowSelected {
			return -1
		}

		match := m.data.Matches[i]
		if filterMatchFound(match, expr) {
			return i
		}
	}
}

func (m model) findPrevious(expr string) int {
	i := m.dataRowSelected

	for {
		i--
		if i < 0 {
			i = m.lastRowIndex()
		}
		if i == m.dataRowSelected {
			return -1
		}

		match := m.data.Matches[i]
		if filterMatchFound(match, expr) {
			return i
		}
	}
}

func (m model) View() string {
	output := ""
	output += renderHeaderRow()

	output += m.renderRowsWindow(m.dataWindowStart, m.dataWindowSize)

	if m.mode == ModeFilterEntry {
		output += m.filter.View()
	}

	return output
}

func newFilterTextInput() textinput.Model {
	ti := textinput.New()
	ti.Prompt = "Find: "
	ti.Placeholder = "package or vulnerability"

	return ti
}
