package triage

import (
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/openvex/vexctl/internal/triage/table"
	"github.com/openvex/vexctl/pkg/formats"
)

type model struct {
	data formats.Normalized

	dataWindowStart, dataWindowSize int
	dataRowSelected                 int

	mode   Mode
	table  table.Model
	filter textinput.Model
}

type Mode int

const (
	ModeDataScroll Mode = iota
	ModeFilterEntry
)

func New(data formats.Normalized) tea.Model {
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
		table:  table.New(data),
		mode:   ModeDataScroll,
		filter: textinput.Model{},
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

			case "/":
				m.mode = ModeFilterEntry
				m.filter = newFilterTextInput()
				m.filter.Focus()
				return m, textinput.Blink

			case "n":
				if expr := m.filter.Value(); expr != "" {
					updatedTable, err := m.table.FindNext()
					if err == table.NoMatchFound {
						// TODO: handle not found
						break
					}

					m.table = updatedTable
					return m, nil
				}

			case "N":
				if expr := m.filter.Value(); expr != "" {
					updatedTable, err := m.table.FindPrevious()
					if err == table.NoMatchFound {
						// TODO: handle not found
						return m, nil
					}

					m.table = updatedTable
					return m, nil
				}
			}

			m.table, cmd = m.table.Update(msg)
			return m, cmd

		case ModeFilterEntry:
			if msg.String() == "enter" {
				expr := m.filter.Value()
				updatedTable, err := m.table.Find(expr)
				if err == table.NoMatchFound {
					// TODO: handle not found
					return m, nil
				}

				m.table = updatedTable

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
		m.table = m.table.SetHeight(msg.Height)
		return m, nil
	}

	m.filter, cmd = m.filter.Update(msg)
	return m, cmd
}

func (m model) View() string {
	output := ""

	output += m.table.View()

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
