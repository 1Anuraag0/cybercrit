# Cybercrit

> **Pre-commit security analysis** — block vulnerabilities before they're committed.

Cybercrit is a hybrid-analysis CLI that runs as a git pre-commit hook, combining local static analysis with cloud LLM review to catch exploitable vulnerabilities in your code changes.

## Features

- 🔍 **Two-phase analysis** — local semgrep scan + cloud LLM review
- 🛟 **Zero-dep fallback** — 10 hardcoded regex rules (secrets, eval, SQL concat) when semgrep is absent
- ⚡ **Fast** — empty-diff fast path, sub-100ms for typical commits
- 🔑 **BYOK** — bring your own API key (Groq, OpenAI compatible)
- 🧠 **Cross-file context** — detects auth bypasses across middleware + routes (capped: 3 files, 50 lines, signatures only)
- 🎯 **Smart filtering** — extension blocklist, token budget truncation, confidence scoring
- 🎨 **Interactive TUI** — review findings, apply patches, view diffs with color
- 📋 **Audit trail** — every decision logged to `~/.cybercrit/<repo>/audit.jsonl` (never committed)
- 🚫 **Commit blocking** — ERROR/CRITICAL findings block the commit
- 🔓 **Audited bypass** — `cybercrit bypass --reason "hotfix" --ttl 1` with one-time signed tokens
- 🕵️ **--no-verify detection** — post-commit hook catches teammates skipping the hook
- 📊 **Trend reporting** — `cybercrit report` with `--format json` for CI/Slack integration
- ⏰ **Scheduled reports** — `cybercrit report-cron` installs weekly cron/schtasks
- 📦 **Versioned rules** — `cybercrit rules version|list|update` for rule management
- 💬 **Suppression** — `// cybercrit-ignore` to skip known false positives

## Installation

```sh
# Build from source
go build -o cybercrit ./cmd/cybercrit/

# Install git hooks (pre-commit + post-commit)
cybercrit install

# Remove hooks
cybercrit uninstall
```

## Commands

| Command | Description |
|---------|-------------|
| `cybercrit install` | Install pre-commit + post-commit hooks |
| `cybercrit uninstall` | Remove hooks |
| `cybercrit scan` | Scan staged changes |
| `cybercrit bypass --reason "..." --ttl 1` | One-time audited bypass |
| `cybercrit report --days 30` | Security trend report (human-readable) |
| `cybercrit report --format json` | Machine-readable report for pipelines |
| `cybercrit report-cron --schedule weekly` | Install weekly report cron job |
| `cybercrit rules list` | Show all bundled detection rules |
| `cybercrit rules version` | Show rules version |
| `cybercrit rules update` | Check for rule updates |

## Configuration

Create `.cybercrit.toml` in your repo root:

```toml
[phase1]
enabled = true

[phase2]
enabled = true
provider = "groq"          # or "openai"
model = "llama-3.3-70b-versatile"
timeout_seconds = 5
max_tokens = 4096

[filter]
blocked_extensions = [".lock", ".sum", ".min.js", ".min.css", ".png", ".jpg", ".pdf"]
max_file_size_kb = 512

[rules]
version = "1.0.0"
```

## API Keys

```sh
export GROQ_API_KEY="your-key-here"
# or
export OPENAI_API_KEY="your-key-here"
# or universal override
export CYBERCRIT_API_KEY="your-key-here"
```

## Architecture

```
cmd/cybercrit/main.go       → entry point
internal/cli/                → cobra commands (scan, install, uninstall, bypass, report, rules, cron)
internal/diff/               → git diff --cached parser
internal/config/             → TOML configuration loader
internal/analyzer/           → semgrep runner, fallback regex rules (v1.0.0), dedup, suppression
internal/llm/                → LLM client, prompt builder, JSON parser, cross-file context fetcher
internal/tui/                → bubbletea interactive reviewer
internal/patch/              → git apply --cached patch engine
internal/audit/              → JSONL audit logger (~/.cybercrit/)
internal/bypass/             → one-time signed bypass tokens
internal/hook/               → pre-commit + post-commit hook manager
```

## License

MIT
