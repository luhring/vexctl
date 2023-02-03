package details

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/openvex/vexctl/pkg/formats"
)

var (
	detailsStyle    = lipgloss.NewStyle().Background(lipgloss.Color("#222233"))
	fieldNameStyle  = lipgloss.NewStyle().Inherit(detailsStyle).Foreground(lipgloss.Color("#aaaaaa"))
	fieldValueStyle = lipgloss.NewStyle().Inherit(detailsStyle).Foreground(lipgloss.Color("#ffffff"))
)

type Model struct {
	height, width int

	data formats.Match
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(_ tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}

func (m Model) View() string {
	output := ""
	output += m.renderFieldNameValue("Package", m.data.Package.Name) + "\n"
	output += m.renderFieldNameValue("Version", m.data.Package.Version) + "\n"
	output += m.renderFieldNameValue("Type", m.data.Package.Type) + "\n"
	output += m.renderFieldNameValue("Origin", m.data.Package.OriginPackageName) + "\n"
	output += m.renderLocations(m.data.Package.Locations) + "\n"

	output += "\n"

	output += m.renderFieldNameValue("Vulnerability", m.data.Vulnerability.ID) + "\n"
	output += m.renderFieldNameValue("Severity", m.data.Vulnerability.Severity) + "\n"
	output += m.renderFieldNameValue("URL", m.data.Vulnerability.URL) + "\n"
	output += m.renderFieldNameValue("Description", m.data.Vulnerability.Description)

	return detailsStyle.Height(m.height).MaxHeight(m.height).Width(m.width).Render(output)
}

func (m Model) SetHeight(h int) Model {
	m.height = h
	return m
}

func (m Model) SetWidth(w int) Model {
	m.width = w
	return m
}

func (m Model) For(data formats.Match) Model {
	m.data = data
	return m
}

func (m Model) renderFieldNameValue(name, value string) string {
	renderedName := fieldNameStyle.Render(name + ":")
	renderedName = stripANSIReset(renderedName)
	renderedValue := fieldValueStyle.Render(value)

	line := renderedName + " " + renderedValue

	return line
}

func (m Model) renderLocations(locations []string) string {
	switch len(locations) {
	case 0:
		return m.renderFieldNameValue("Location", "")
	case 1:
		return m.renderFieldNameValue("Location", locations[0])
	default:
		values := strings.Join(locations, "\n")
		return m.renderFieldNameValue("Locations", values)
	}
}

func stripANSIReset(in string) string {
	const resetSequence = "\x1b[0m"
	return strings.Replace(in, resetSequence, "", -1)
}
