package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/cybercrit/cybercrit/internal/analyzer"
	"github.com/cybercrit/cybercrit/internal/config"
	"github.com/cybercrit/cybercrit/internal/diff"
	"github.com/cybercrit/cybercrit/internal/llm"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Scan staged changes for security issues",
		Long: `Scan staged git changes using local static analysis (Phase 1) and
optionally cloud LLM analysis (Phase 2). This is the command invoked
by the pre-commit hook.`,
		RunE: runScan,
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	start := time.Now()

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	// Load configuration
	cfg, err := config.Load(wd)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Get staged diffs
	diffs, err := diff.Staged(wd)
	if err != nil {
		return fmt.Errorf("get staged diffs: %w", err)
	}

	// Empty-diff fast path (CORE-05)
	if len(diffs) == 0 {
		return nil // nothing staged — exit 0 immediately
	}

	// Filter blocked extensions (CORE-06)
	var filtered []diff.FileDiff
	for _, d := range diffs {
		if cfg.IsBlocked(d.Path) {
			continue
		}
		filtered = append(filtered, d)
	}

	if len(filtered) == 0 {
		return nil
	}

	// ─── Phase 1: Local Static Analysis ────────────────────────────

	var findings []analyzer.Finding

	if cfg.Phase1.Enabled {
		if !analyzer.SemgrepAvailable() {
			fmt.Println("⚠ semgrep not found — skipping local analysis (install: pip install semgrep)")
		} else {
			semgrepFindings, err := analyzer.RunSemgrep(filtered, wd)
			if err != nil {
				fmt.Printf("⚠ semgrep error: %v (continuing without local analysis)\n", err)
			} else {
				findings = append(findings, semgrepFindings...)
			}
		}
	}

	// ─── Phase 2: LLM Analysis ────────────────────────────────────

	if cfg.Phase2.Enabled {
		client, err := llm.NewClient(cfg.Phase2.Provider, cfg.Phase2.Model, cfg.Phase2.TimeoutS)
		if err != nil {
			fmt.Printf("⚠ LLM setup error: %v (continuing without LLM analysis)\n", err)
		} else if client == nil {
			fmt.Println("⚠ no API key found — skipping LLM analysis (set GROQ_API_KEY or OPENAI_API_KEY)")
		} else {
			// Build prompt with token budget truncation (LLM-02)
			userPrompt := llm.BuildUserPrompt(filtered, cfg.Phase2.MaxTokens)

			// Call LLM with hard timeout (LLM-04)
			response, err := client.Complete(llm.SystemPrompt(), userPrompt)
			if err != nil {
				fmt.Printf("⚠ LLM error: %v (continuing without LLM analysis)\n", err)
			} else {
				// Parse response with strict JSON schema (LLM-03) and confidence filter (LLM-05)
				llmFindings, err := llm.ParseResponse(response, 0.70)
				if err != nil {
					fmt.Printf("⚠ LLM parse error: %v (continuing without LLM findings)\n", err)
				} else {
					findings = append(findings, llmFindings...)
				}
			}
		}
	}

	// ─── Post-processing ──────────────────────────────────────────

	// Build suppression set from diff annotations
	suppressed := analyzer.SuppressedLines(filtered)

	// Filter suppressed lines
	findings = analyzer.FilterSuppressed(findings, suppressed)

	// Deduplicate
	findings = analyzer.Deduplicate(findings)

	// ─── Results ───────────────────────────────────────────────────

	elapsed := time.Since(start)

	if len(findings) == 0 {
		fmt.Printf("cybercrit: scanned %d file(s) in %s — no issues found ✓\n",
			len(filtered), elapsed.Round(time.Millisecond))
		return nil
	}

	// Count by severity
	counts := map[analyzer.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	// Print findings
	fmt.Printf("cybercrit: scanned %d file(s) in %s\n\n",
		len(filtered), elapsed.Round(time.Millisecond))

	for _, f := range findings {
		icon := severityIcon(f.Severity)
		fmt.Printf("  %s [%s] %s:%d — %s\n", icon, f.Severity, f.Path, f.Line, f.RuleID)
		fmt.Printf("    %s\n", f.Message)
		if f.Source == "llm" && f.Confidence > 0 {
			fmt.Printf("    confidence: %.0f%%\n", f.Confidence*100)
		}
		if f.Patch != "" {
			fmt.Printf("    💡 auto-fix available\n")
		}
		fmt.Println()
	}

	// Summary line
	fmt.Printf("  %d finding(s)", len(findings))
	if c := counts[analyzer.SeverityCritical]; c > 0 {
		fmt.Printf(" · %d critical", c)
	}
	if c := counts[analyzer.SeverityError]; c > 0 {
		fmt.Printf(" · %d error", c)
	}
	if c := counts[analyzer.SeverityWarning]; c > 0 {
		fmt.Printf(" · %d warning", c)
	}
	fmt.Println()

	// Block commit on HIGH/CRITICAL findings
	blocking := counts[analyzer.SeverityError] + counts[analyzer.SeverityCritical]
	if blocking > 0 {
		fmt.Printf("\n  ✗ commit blocked: %d critical/high finding(s)\n", blocking)
		return fmt.Errorf("commit blocked: %d critical/high findings", blocking)
	}

	return nil
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
