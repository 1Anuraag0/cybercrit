# PROJECT.md Template

# Cybercrit

## What This Is
A freemium, hybrid-analysis CLI for git pre-commit security review. It features a zero-repo-scan architecture utilizing local static analysis (Phase 1) and cloud LLM analysis on diff delta only (Phase 2), aimed at preventing vulnerable code from being committed.

## Core Value
Block real, exploitable vulnerabilities locally before they are committed, without slowing down the developer workflow with massive context dumps, false positives, or noisy rate limits.

## Requirements

### Validated
(None yet — ship to validate)

### Active
- [ ] Implement fast local static analysis using semgrep as a subprocess wrapper.
- [ ] Implement LLM integration via Groq for API requests targeting only added lines in diffs.
- [ ] Bubbletea interactive console UI for reviewing vulnerabilities with apply/ignore options.
- [ ] Graceful degradation to ignore rules permanently or bypass temporarily.
- [ ] Enforce confidence thresholds and deduplication of findings.

### Out of Scope
- [ ] Running full repository scans — Focus entirely on the immediate diff line additions.
- [ ] Analyzing unchanged or removed lines — Too heavy and slow context window.

## Context
Target language for the project is Go 1.22+. Go was explicitly chosen over Rust because 4ms startup difference is dwarfed by network latency, and Go enables simple, zero-native-dependency static binaries built across macOS/Linux/Windows via `goreleaser`.
The app functions as a `pre-commit` hook using an auto-installed script hook.

## Constraints
- **Performance**: Hook execution for Phase 1 must be < 80ms, Phase 2 < 3s (p95).
- **Size & Portability**: Needs to be a single static binary (~4MB) with zero external dependency (no python/venv).
- **API Strategy**: Defaults to BYOK (Bring Your Own Key) using OS keychain, with fallbacks.
- **Data Boundaries**: Never run LLM on `.lock`, `.sum`, generated, or `min.js` files; strict truncation threshold (3500 tokens).

## Key Decisions
| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Go instead of Rust | Trivial cross-compilation without CGO/no dependency needs | — Pending |
| Phase 1 + 2 architecture | Keep costs low/free by using fast semantic scanning first, gating expensive API calls | — Pending |
| Interactive TUI prompt | Ensure developer retains authority to block, apply patch, or bypass rules | — Pending |

---
*Last updated: 2026-04-12 after initialization*

## Evolution
This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state
