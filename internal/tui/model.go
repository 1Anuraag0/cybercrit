package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cybercrit/cybercrit/internal/analyzer"
)

// Action is what the user chose for a finding.
type Action int

const (
	ActionSkip  Action = iota // do nothing
	ActionApply               // apply the patch
	ActionView                // view-only (patch failed dry-run)
)

// Result captures the user's decision for a single finding.
type Result struct {
	Finding analyzer.Finding
	Action  Action
}

// Model is the Bubbletea model for the interactive finding reviewer.
type Model struct {
	findings []analyzer.Finding
	results  []Result
	cursor   int
	done     bool
	width    int
	height   int
	viewMode bool // true when viewing patch details
}

// New creates a new TUI model from findings.
func New(findings []analyzer.Finding) Model {
	return Model{
		findings: findings,
		results:  make([]Result, 0, len(findings)),
		cursor:   0,
		width:    80,
		height:   24,
	}
}

// Results returns the user's decisions after the TUI exits.
func (m Model) Results() []Result {
	return m.results
}

// Done returns true if the user has reviewed all findings.
func (m Model) Done() bool {
	return m.done
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		if m.done {
			return m, tea.Quit
		}

		switch msg.String() {
		case "q", "ctrl+c":
			// Skip remaining findings and quit
			for i := m.cursor; i < len(m.findings); i++ {
				m.results = append(m.results, Result{
					Finding: m.findings[i],
					Action:  ActionSkip,
				})
			}
			m.done = true
			return m, tea.Quit

		case "a": // apply patch
			if m.cursor < len(m.findings) {
				f := m.findings[m.cursor]
				if f.Patch != "" {
					m.results = append(m.results, Result{
						Finding: f,
						Action:  ActionApply,
					})
				} else {
					m.results = append(m.results, Result{
						Finding: f,
						Action:  ActionSkip,
					})
				}
				m.cursor++
				if m.cursor >= len(m.findings) {
					m.done = true
					return m, tea.Quit
				}
			}

		case "s": // skip
			if m.cursor < len(m.findings) {
				m.results = append(m.results, Result{
					Finding: m.findings[m.cursor],
					Action:  ActionSkip,
				})
				m.cursor++
				if m.cursor >= len(m.findings) {
					m.done = true
					return m, tea.Quit
				}
			}

		case "v": // view patch
			m.viewMode = !m.viewMode
		}
	}

	return m, nil
}

// View implements tea.Model.
func (m Model) View() string {
	if m.done {
		return m.renderSummary()
	}

	if m.cursor >= len(m.findings) {
		return ""
	}

	f := m.findings[m.cursor]
	var sb strings.Builder

	// Header
	sb.WriteString(headerStyle.Render(fmt.Sprintf(
		" cybercrit — finding %d/%d ",
		m.cursor+1, len(m.findings),
	)))
	sb.WriteString("\n\n")

	// Severity + Rule
	icon := severityIcon(f.Severity)
	sevStyle := severityStyle(f.Severity)
	sb.WriteString(fmt.Sprintf("  %s %s  %s\n",
		icon,
		sevStyle.Render(f.Severity.String()),
		ruleStyle.Render(f.RuleID),
	))

	// Location
	sb.WriteString(fmt.Sprintf("  %s\n\n",
		locationStyle.Render(fmt.Sprintf("%s:%d", f.Path, f.Line)),
	))

	// Message
	sb.WriteString(fmt.Sprintf("  %s\n\n", f.Message))

	// Source + Confidence
	if f.Source == "llm" && f.Confidence > 0 {
		sb.WriteString(fmt.Sprintf("  source: %s  confidence: %.0f%%\n\n",
			sourceStyle.Render("LLM"),
			f.Confidence*100,
		))
	} else if f.Source == "semgrep" {
		sb.WriteString(fmt.Sprintf("  source: %s\n\n",
			sourceStyle.Render("semgrep"),
		))
	}

	// Patch view
	if m.viewMode && f.Patch != "" {
		sb.WriteString(renderPatch(f.Patch))
		sb.WriteString("\n")
	}

	// Controls
	sb.WriteString(dividerStyle.Render(strings.Repeat("─", min(m.width, 60))))
	sb.WriteString("\n")

	if f.Patch != "" {
		sb.WriteString("  [a] apply fix  [s] skip  [v] view patch  [q] quit\n")
	} else {
		sb.WriteString("  [s] skip  [q] quit\n")
	}

	return sb.String()
}

func (m Model) renderSummary() string {
	applied := 0
	skipped := 0
	for _, r := range m.results {
		switch r.Action {
		case ActionApply:
			applied++
		case ActionSkip:
			skipped++
		}
	}

	return fmt.Sprintf("\n  ✓ Review complete: %d applied, %d skipped\n\n",
		applied, skipped)
}

func renderPatch(patch string) string {
	var sb strings.Builder
	sb.WriteString("  ┌─ patch ───────────────────────────────\n")
	for _, line := range strings.Split(patch, "\n") {
		var styled string
		if strings.HasPrefix(line, "+") {
			styled = addStyle.Render(line)
		} else if strings.HasPrefix(line, "-") {
			styled = delStyle.Render(line)
		} else if strings.HasPrefix(line, "@@") {
			styled = hunkStyle.Render(line)
		} else {
			styled = line
		}
		sb.WriteString("  │ " + styled + "\n")
	}
	sb.WriteString("  └──────────────────────────────────────\n")
	return sb.String()
}

func severityIcon(s analyzer.Severity) string {
	switch s {
	case analyzer.SeverityCritical:
		return "🔴"
	case analyzer.SeverityError:
		return "🟠"
	case analyzer.SeverityWarning:
		return "🟡"
	default:
		return "🔵"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Styles ────────────────────────────────────────────────────────

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Background(lipgloss.Color("#7C3AED")).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1)

	ruleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A78BFA")).
			Bold(true)

	locationStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280"))

	sourceStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#60A5FA")).
			Italic(true)

	dividerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#374151"))

	addStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#34D399"))

	delStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F87171"))

	hunkStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#60A5FA"))
)

func severityStyle(s analyzer.Severity) lipgloss.Style {
	switch s {
	case analyzer.SeverityCritical:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Bold(true)
	case analyzer.SeverityError:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#F97316")).Bold(true)
	case analyzer.SeverityWarning:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#EAB308")).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#3B82F6"))
	}
}
