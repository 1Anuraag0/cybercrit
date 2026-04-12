# Cybercrit

> **Pre-commit security analysis** — block vulnerabilities before they're committed.

Cybercrit is a hybrid-analysis CLI that runs as a git pre-commit hook, combining local static analysis (semgrep) with cloud LLM review to catch exploitable vulnerabilities in your code changes.

## Features

- 🔍 **Two-phase analysis** — local semgrep scan + cloud LLM review
- ⚡ **Fast** — empty-diff fast path, sub-100ms for typical commits
- 🔑 **BYOK** — bring your own API key (Groq, OpenAI compatible)
- 🛡️ **Smart filtering** — extension blocklist, token budget truncation, confidence scoring
- 🎨 **Interactive TUI** — review findings, apply patches, view diffs with color
- 📋 **Audit trail** — every decision logged to `audit.jsonl`
- 🚫 **Commit blocking** — HIGH/CRITICAL findings block the commit
- 💬 **Suppression** — `// cybercrit-ignore` to skip known false positives

## Installation

```sh
# Build from source
go build -o cybercrit ./cmd/cybercrit/

# Install the git hook
cybercrit install

# Remove the hook
cybercrit uninstall
```

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
```

## API Keys

Set your API key via environment variable:

```sh
export GROQ_API_KEY="your-key-here"
# or
export OPENAI_API_KEY="your-key-here"
# or universal override
export CYBERCRIT_API_KEY="your-key-here"
```

## Usage

```sh
# Manual scan
cybercrit scan

# Automatic via pre-commit hook (after `cybercrit install`)
git commit -m "your changes"  # cybercrit runs automatically
```

## Architecture

```
cmd/cybercrit/main.go       → entry point
internal/cli/                → cobra commands (scan, install, uninstall)
internal/diff/               → git diff --cached parser
internal/config/             → TOML configuration loader
internal/analyzer/           → semgrep runner, dedup, suppression
internal/llm/                → LLM client, prompt builder, JSON parser
internal/tui/                → bubbletea interactive reviewer
internal/patch/              → git apply --cached patch engine
internal/audit/              → JSONL audit logger
internal/hook/               → pre-commit hook file manager
```

## License

MIT
