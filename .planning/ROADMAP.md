# Roadmap: Cybercrit

**Defined:** 2026-04-12
**Core Value:** Block real, exploitable vulnerabilities locally before they are committed.

## Phase 1: CLI Skeleton + Hook Infrastructure
**Goal:** Working hook that captures and prints diffs — zero analysis.
- [ ] **CORE-01**: Provide `cybercrit install` to write bash wrapper hook.
- [ ] **CORE-02**: Provide `cybercrit uninstall` to remove hook.
- [ ] **CORE-03**: Create internal/diff package for `git diff --cached` execution.
- [ ] **CORE-04**: Global & repo-local configuration system (`.cybercrit.toml`).
- [ ] **CORE-05**: Implement an "empty-diff fast path".
- [ ] **CORE-06**: Filter massive diffs based on config extension blocklists.

## Phase 2: Local Static Analysis Engine
**Goal:** Sub-80ms semgrep scan, deterministic block on HIGH findings.
- [ ] **ANLZ-01**: Execute `semgrep` on diff added lines through a temporary file.
- [ ] **ANLZ-02**: Gracefully skip Phase 1 if `semgrep` is unavailable.
- [ ] **ANLZ-03**: Deduplicate findings based on rule ID and line content.
- [ ] **ANLZ-04**: Support parsing suppression annotations (`// cybercrit-ignore`).

## Phase 3: LLM Integration + BYOK
**Goal:** Working Groq API call, JSON response parsed, finding printed to terminal.
- [ ] **LLM-01**: Interact with Groq/OpenAI compatible API using BYOK credential chain.
- [ ] **LLM-02**: Truncate token budget intelligently, dropping lowest-complexity hunks.
- [ ] **LLM-03**: Enforce LLM response into strict JSON schema with regex validation.
- [ ] **LLM-04**: Apply a hard timeout of 5s on API, fail gracefully.
- [ ] **LLM-05**: Filter findings below 0.70 confidence score entirely.

## Phase 4: Interactive TUI + Automated Patch Apply
**Goal:** Bubbletea-powered interactive fix workflow, git apply integration.
- [ ] **UI-01**: Interactive UI using Bubbletea with color-coded diff syntax highlighting.
- [ ] **UI-02**: Patch application using `git apply --cached --index`.
- [ ] **UI-03**: Maintain audit logging (`audit.jsonl`).
- [ ] **UI-04**: Safe patch dry-run; replace Y with V.

---
*Roadmap defined: 2026-04-12*
*Last updated: 2026-04-12 after initial definition*
