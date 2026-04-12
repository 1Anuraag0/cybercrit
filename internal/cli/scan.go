package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/cybercrit/cybercrit/internal/config"
	"github.com/cybercrit/cybercrit/internal/diff"
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
			continue // skip blocked extensions
		}
		filtered = append(filtered, d)
	}

	// If everything was filtered out, exit clean
	if len(filtered) == 0 {
		return nil
	}

	// Print summary of staged files (placeholder for Phase 2/3 analysis)
	elapsed := time.Since(start)
	fmt.Printf("cybercrit: scanned %d file(s) in %s\n", len(filtered), elapsed.Round(time.Millisecond))
	for _, d := range filtered {
		adds := 0
		for _, h := range d.Hunks {
			for _, l := range h.Lines {
				if l.Kind == diff.KindAdd {
					adds++
				}
			}
		}
		fmt.Printf("  %s (+%d lines)\n", d.Path, adds)
	}

	return nil
}
