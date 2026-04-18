<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗██████╗ ██╗████████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗██║╚══██╔══╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     ██████╔╝██║   ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║     ██╔══██╗██║   ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚██████╗██║  ██║██║   ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝
```

**Security analysis that runs before the damage is done.**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)]()

</div>

---

Cybercrit installs as a `git pre-commit` hook. The moment you run `git commit`, it extracts only your staged diff, runs a two-phase analysis pipeline, and either passes the commit silently or blocks it with an interactive terminal showing exactly what's wrong and how to fix it — including an AI-generated, dry-run-validated patch you can apply with a single keypress.

Zero repo scanning. Zero false positives on untouched code. Sub-100ms for the common path.

```
$ git commit -m "add user lookup endpoint"

  cybercrit — analyzing 3 files (47 added lines)...

  ┌─ CRITICAL ──────────────────────────────────────────────────────┐
  │  SQL Injection                              CWE-89 · conf 1.00  │
  │  handlers/user.go:42                                            │
  │                                                                 │
  │  - query := "SELECT * FROM users WHERE id=" + userID            │
  │  + query, args := "SELECT * FROM users WHERE id=?", userID      │
  │                                                                 │
  │  analyzed by gemini-2.0-flash in 847ms                          │
  │                                                                 │
  │  [a] apply fix   [s] skip   [i] ignore rule   [q] abort         │
  └─────────────────────────────────────────────────────────────────┘
```

---

## How it works

Cybercrit runs two phases in sequence on every commit.

**Phase 1 — Local (< 80ms).** Semgrep scans only the added lines, written to a temp file with the correct extension so language rules match correctly. If semgrep is not installed, 10 compiled-regex fallback rules cover the highest-signal patterns: hardcoded AWS keys, private key headers, SQL string concatenation, `eval()`, `sslmode=disable`, hardcoded passwords, weak hashes, CORS wildcards, debug flags, and generic token patterns. The regex agent always runs — it has no dependencies and cannot fail.

**Phase 2 — Cloud LLM (< 3s).** Only triggered if Phase 1 finds nothing obvious or if the diff complexity score exceeds a threshold. The diff (added lines only, stripped of removes) is sent to the configured agent chain. Each agent implements the same interface — if one fails, the next takes over with no user-visible error.

```
Gemini 2.0 Flash  →  OpenRouter (Mistral-7B)  →  Ollama (local)  →  regex-builtin
    primary            region fallback           offline mode       always-on floor
```

The LLM is instructed to return a strict JSON schema including a `fixed_line` field — a ready-to-apply single-line replacement. Before showing the fix to the user, Cybercrit runs `git apply --check` on it. If the patch won't apply cleanly, the apply button is disabled and replaced with a view-only mode. No broken patches ever touch your index.

---

## Installation

```sh
# Build from source
go build -o cybercrit ./cmd/cybercrit/
sudo mv cybercrit /usr/local/bin/

# Install hooks into the current repo
cybercrit install

# First-time setup (optional: pull local model for offline mode)
cybercrit setup
# → checks for Ollama, pulls gemma3:4b if available
```

**Verify it's working:**

```sh
# Scan staged changes manually (outside the hook)
cybercrit scan

# Create a test file with a known vulnerability and stage it
echo 'query := "SELECT * FROM users WHERE id=" + userID' > /tmp/test.go
git add /tmp/test.go
git commit -m "test"
# cybercrit should block with a CRITICAL finding
```

---

## Agent chain & API keys

Cybercrit resolves credentials in priority order and builds the chain from whatever is available. If nothing is configured, the regex fallback fires silently.

```sh
# Primary (recommended) — works in all regions
export GEMINI_API_KEY="..."        # aistudio.google.com — free 1500 req/day

# Secondary fallback
export OPENROUTER_API_KEY="..."    # openrouter.ai — free tier, no region blocks

# Universal override (sets all agents if specific keys are absent)
export CYBERCRIT_API_KEY="..."

# Local inference (no data leaves your machine)
ollama pull gemma3:4b
# set local_model = "gemma3:4b" in .cybercrit.toml
```

Credential resolution order per agent: (1) specific env var → (2) `CYBERCRIT_API_KEY` → (3) `.cybercrit.toml` field → (4) agent skipped.

---

## Configuration

Create `.cybercrit.toml` in your repo root. All fields are optional — Cybercrit works with zero config using env vars alone.

```toml
# Inference backend: "hybrid" | "cloud" | "local"
inference = "hybrid"

# Local model (requires Ollama)
local_model = "gemma3:4b"

# Agent keys (prefer env vars over committing keys here)
# gemini_api_key     = ""
# openrouter_api_key = ""

[phase1]
enabled = true

[phase2]
enabled    = true
timeout    = "5s"
max_tokens = 4096

[filter]
# Files matching these extensions are never sent to Phase 2
blocked_extensions = [
  ".lock", ".sum", ".snap",
  ".min.js", ".min.css",
  ".pb.go", "_gen.go",
  ".png", ".jpg", ".pdf", ".svg"
]
max_file_size_kb = 512

[rules]
version = "1.0.0"

# Permanently ignore a rule in this repo
# [[ignore]]
# rule_id   = "no-sql-concat"
# file_glob = "internal/test/**"
```

---

## Commands

| Command | What it does |
|---|---|
| `cybercrit install` | Write pre-commit + post-commit hooks to `.git/hooks/` |
| `cybercrit uninstall` | Remove hooks, restore any backup |
| `cybercrit setup` | Check Ollama, pull configured local model |
| `cybercrit scan` | Scan staged changes (same as the hook, run manually) |
| `cybercrit scan --file path/to/file.go` | Scan a specific file |
| `cybercrit bypass --reason "hotfix" --ttl 1` | One-time signed bypass token (audited) |
| `cybercrit report` | 30-day severity trend, top rules, bypass history |
| `cybercrit report --days 90 --format json` | Machine-readable report for CI / Slack |
| `cybercrit report-cron --schedule weekly` | Install weekly cron job (cron on Linux/macOS, schtasks on Windows) |
| `cybercrit rules list` | Show all active detection rules |
| `cybercrit rules version` | Show current rule bundle version |
| `cybercrit rules update` | Pull latest rule bundle |
| `cybercrit log-skip` | View skipped findings from audit log |

---

## Suppression

Add a comment on the offending line to suppress a specific finding. Cybercrit's diff parser strips these before the severity gate — they never affect blocking logic for other findings.

```go
// This token is a placeholder — replaced at deploy time
apiToken := "changeme-replace-in-prod" // cybercrit-ignore

# Python
password = os.getenv("DB_PASSWORD", "devonly") # cybercrit-ignore
```

To permanently ignore a rule across a file glob, add it to `.cybercrit.toml`:

```toml
[[ignore]]
rule_id   = "no-hardcoded-secret"
file_glob = "internal/testdata/**"
```

---

## Bypass

When you need to commit without running the scan (hotfix, emergency, infra incident), use the audited bypass. It skips the hook exactly once and logs the reason.

```sh
cybercrit bypass --reason "prod is down, rolling back migration" --ttl 1
# → writes a signed one-time token to .git/cybercrit-bypass
# → next git commit skips analysis and logs the bypass to audit.jsonl
# → token is invalid after one use
```

The post-commit hook also detects `git commit --no-verify` runs and logs them to `audit.jsonl` with a `no-verify` flag so they appear in `cybercrit report`.

---

## Audit trail

Every decision made during a scan is appended to `~/.cybercrit/<repo-hash>/audit.jsonl`. This file is never committed.

```json
{
  "ts": "2026-04-18T11:32:01Z",
  "finding_id": "a3f9c1b2",
  "severity": "CRITICAL",
  "vuln_class": "INJECTION",
  "file": "handlers/user.go",
  "line": 42,
  "agent": "gemini-2.0-flash",
  "confidence": 1.0,
  "action": "applied",
  "repo": "cybercrit-demo"
}
```

`cybercrit report` reads this file to produce severity trends, top rules fired, bypass history, and improving/worsening signals over your configured window.

---

## CI / CD

In CI environments (`$CI=true` or no TTY), Cybercrit automatically drops the interactive TUI and prints machine-readable output to stderr. Findings are JSON. Exit code is 1 on ERROR/CRITICAL.

```yaml
# GitHub Actions example
- name: cybercrit scan
  run: |
    go build -o cybercrit ./cmd/cybercrit/
    git diff --cached | cybercrit scan --stdin --format json
  env:
    GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

```sh
# Pipe findings to jq
cybercrit scan --format json | jq '.findings[] | select(.severity == "CRITICAL")'
```

---

## Architecture

```
cmd/cybercrit/
└── main.go                   entry point, cobra root

internal/
├── cli/
│   ├── scan.go               orchestrates phase 1 → phase 2 → TUI
│   ├── install.go            hook writer + backup logic
│   ├── uninstall.go
│   ├── bypass.go             signed token generation + validation
│   ├── report.go             audit.jsonl reader + trend renderer
│   ├── cron.go               cron/schtasks installer
│   ├── logskip.go
│   └── rules.go              rule version management
│
├── diff/
│   ├── parser.go             git diff --cached → []FileDiff
│   └── extractor.go          added-lines-only extraction
│
├── analyzer/
│   ├── semgrep.go            subprocess wrapper, 2s timeout, graceful skip
│   ├── fallback.go           10 compiled-regex rules (v1.0.0)
│   ├── findings.go           Finding type, severity constants
│   ├── dedup.go              hash(rule_id + line_content) deduplication
│   └── suppress.go           cybercrit-ignore parser
│
├── llm/
│   ├── agent.go              Agent interface, AnalyzeRequest, AnalysisResult
│   ├── chain.go              AgentChain.Analyze(), confidence escalation, NewDefaultChain()
│   ├── prompt.go             SystemPrompt const, BuildUserMessage(), StripFences()
│   ├── gemini.go             GeminiAgent — primary cloud backend
│   ├── openrouter.go         OpenRouterAgent — regional fallback
│   ├── ollama.go             OllamaAgent — local inference, 200ms health check
│   ├── regex.go              RegexAgent — zero-dep safety net, always available
│   └── http.go               buildOpenAIRequest(), parseOpenAIResponse() shared helpers
│
├── tui/
│   └── reviewer.go           bubbletea finding reviewer + keypress handler
│
├── patch/
│   └── apply.go              git apply --check → git apply --cached pipeline
│
├── audit/
│   └── logger.go             JSONL append to ~/.cybercrit/<repo>/audit.jsonl
│
├── bypass/
│   └── token.go              HMAC-signed one-time token lifecycle
│
├── hook/
│   └── manager.go            pre-commit + post-commit install/uninstall
│
└── config/
    └── config.go             TOML loader, env var resolution, credential chain
```

**Key invariants:**
- `llm.Finding` and `analyzer.Finding` are separate types. Mapping happens only in `cli/scan.go`.
- The regex agent is always the last entry in `AgentChain` — it cannot be removed and `Available()` always returns `true`.
- `git apply --check` is always called before `git apply --cached`. A patch that fails the check is never applied.
- Phase 2 failure (all agents exhausted) is a warning, not an exit 1. The commit is never blocked by infrastructure failure.
- Empty diff (`len(addedLines) == 0`) exits 0 in under 10ms with no output.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
<sub>built with Go · no repo scanning · no telemetry by default · your code stays yours</sub>
</div>
