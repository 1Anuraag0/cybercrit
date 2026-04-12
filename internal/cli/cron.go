package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func newReportCronCmd() *cobra.Command {
	var schedule string
	var outputFile string
	var uninstall bool

	cmd := &cobra.Command{
		Use:   "report-cron",
		Short: "Install/uninstall a weekly cron job for security reports",
		Long: `Install a cron job (Linux/macOS) or scheduled task (Windows) that runs
cybercrit report --format json weekly and writes to a file.

Leads can then set up a webhook, email forwarder, or Slack integration
that reads the JSON output.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return err
			}

			cybercritPath, err := os.Executable()
			if err != nil {
				// Fallback to PATH lookup
				cybercritPath = "cybercrit"
			}

			if uninstall {
				return uninstallCron()
			}

			if outputFile == "" {
				home, _ := os.UserHomeDir()
				repoName := filepath.Base(wd)
				outputFile = filepath.Join(home, ".cybercrit", repoName, "weekly-report.json")
			}

			// Ensure output directory exists
			os.MkdirAll(filepath.Dir(outputFile), 0o755)

			return installCron(cybercritPath, wd, outputFile, schedule)
		},
	}

	cmd.Flags().StringVar(&schedule, "schedule", "weekly", "cron schedule: daily, weekly, or a cron expression")
	cmd.Flags().StringVar(&outputFile, "output", "", "output file path (default: ~/.cybercrit/<repo>/weekly-report.json)")
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove the cron job")

	return cmd
}

const cronMarker = "# cybercrit-report-cron"

func installCron(cybercritPath, workDir, outputFile, schedule string) error {
	if runtime.GOOS == "windows" {
		return installWindowsTask(cybercritPath, workDir, outputFile, schedule)
	}
	return installUnixCron(cybercritPath, workDir, outputFile, schedule)
}

func installUnixCron(cybercritPath, workDir, outputFile, schedule string) error {
	cronExpr := "0 9 * * 1" // default: Monday 9am
	switch schedule {
	case "daily":
		cronExpr = "0 9 * * *"
	case "weekly":
		cronExpr = "0 9 * * 1"
	default:
		if strings.Contains(schedule, "*") {
			cronExpr = schedule
		}
	}

	cronLine := fmt.Sprintf("%s cd %s && %s report --format json --days 7 > %s 2>&1 %s",
		cronExpr, workDir, cybercritPath, outputFile, cronMarker)

	// Read existing crontab
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		out = []byte{}
	}

	existing := string(out)

	// Remove old cybercrit cron entries
	var lines []string
	for _, line := range strings.Split(existing, "\n") {
		if !strings.Contains(line, cronMarker) {
			lines = append(lines, line)
		}
	}
	lines = append(lines, cronLine)

	// Write new crontab
	newCrontab := strings.Join(lines, "\n") + "\n"
	installCmd := exec.Command("crontab", "-")
	installCmd.Stdin = strings.NewReader(newCrontab)
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("install cron: %w", err)
	}

	fmt.Printf("✓ cron job installed (%s)\n", schedule)
	fmt.Printf("  schedule: %s\n", cronExpr)
	fmt.Printf("  output:   %s\n", outputFile)
	fmt.Printf("  command:  cybercrit report --format json --days 7\n")

	return nil
}

func installWindowsTask(cybercritPath, workDir, outputFile, schedule string) error {
	taskName := "CybercritWeeklyReport"

	// Build schtasks command
	schedFlag := "WEEKLY"
	switch schedule {
	case "daily":
		schedFlag = "DAILY"
	case "weekly":
		schedFlag = "WEEKLY"
	}

	cmdLine := fmt.Sprintf(`cmd /c "cd /d %s && %s report --format json --days 7 > %s 2>&1"`,
		workDir, cybercritPath, outputFile)

	schtasksCmd := exec.Command("schtasks", "/create",
		"/tn", taskName,
		"/tr", cmdLine,
		"/sc", schedFlag,
		"/st", "09:00",
		"/f", // force overwrite
	)

	out, err := schtasksCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("create scheduled task: %s\n%w", string(out), err)
	}

	fmt.Printf("✓ scheduled task created: %s (%s at 09:00)\n", taskName, schedule)
	fmt.Printf("  output: %s\n", outputFile)

	return nil
}

func uninstallCron() error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("schtasks", "/delete", "/tn", "CybercritWeeklyReport", "/f")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("remove scheduled task: %s\n%w", string(out), err)
		}
		fmt.Println("✓ scheduled task removed")
		return nil
	}

	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return fmt.Errorf("no crontab found")
	}

	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, cronMarker) {
			lines = append(lines, line)
		}
	}

	installCmd := exec.Command("crontab", "-")
	installCmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("update crontab: %w", err)
	}

	fmt.Println("✓ cron job removed")
	return nil
}
