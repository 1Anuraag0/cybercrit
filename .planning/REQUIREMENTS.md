# Requirements: Cybercrit

**Defined:** 2026-04-12
**Core Value:** Block real, exploitable vulnerabilities locally before they are committed, without slowing down the developer workflow with massive context dumps, false positives, or noisy rate limits.

## v1 Requirements

### Core CLI & Hook

- [ ] **CORE-01**: Provide `cybercrit install` to write bash wrapper hook to `.git/hooks/pre-commit`.
- [ ] **CORE-02**: Provide `cybercrit uninstall` to remove hook.
- [ ] **CORE-03**: Create internal/diff package for `git diff --cached` execution and parsing into typed format.
- [ ] **CORE-04**: Global & repo-local configuration system (`.cybercrit.toml`).
- [ ] **CORE-05**: Implement an "empty-diff fast path" for zero output exits.
- [ ] **CORE-06**: Filter massive diffs based on config extension blocklists before analysis.

### Local Static Analysis

- [ ] **ANLZ-01**: Execute `semgrep` on diff added lines through a temporary file strategy (<80ms).
- [ ] **ANLZ-02**: Gracefully skip Phase 1 if `semgrep` is unavailable.
- [ ] **ANLZ-03**: Deduplicate findings based on rule ID and line content.
- [ ] **ANLZ-04**: Support parsing suppression annotations (`// cybercrit-ignore`).

### LLM Integration

- [ ] **LLM-01**: Interact with Groq/OpenAI compatible API using BYOK credential chain.
- [ ] **LLM-02**: Truncate token budget intelligently, dropping lowest-complexity hunks first up to 4096.
- [ ] **LLM-03**: Enforce LLM response into strict JSON schema with custom regex validation for patch safety.
- [ ] **LLM-04**: Apply a hard timeout of 5s on API, fail gracefully (non-blocking).
- [ ] **LLM-05**: Filter findings below 0.70 confidence score entirely.

### Navigation and UI

- [ ] **UI-01**: Interactive UI using Bubbletea with color-coded diff syntax highlighting.
- [ ] **UI-02**: Patch application using `git apply --cached --index`.
- [ ] **UI-03**: Maintain audit logging (`audit.jsonl`).
- [ ] **UI-04**: Safe patch dry-run; replace Y with V (view only) if `git apply --check` fails.

## v2 Requirements

### Analytics & Subscription
- **SUBS-01**: Routing to premium endpoints (`api.cybercrit.dev/v1/analyze`) with subscription tokens.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Unmodified source analysis | Too slow, not relevant to code just added |
| Removing existing bugs outside diff | High latency, not a pre-commit goal |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|

**Coverage:**
- v1 requirements: 18 total
- Mapped to phases: 0
- Unmapped: 18 ⚠️

---
*Requirements defined: 2026-04-12*
*Last updated: 2026-04-12 after initial definition*
