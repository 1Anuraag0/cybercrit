# Cybercrit

Cybercrit is a hybrid-analysis CLI that runs as a git pre-commit hook, combining local static analysis (semgrep) with cloud LLM review to catch vulnerabilities before they're committed.

## Installation

```sh
go install github.com/cybercrit/cybercrit@latest
cybercrit install
```

## Features

- Fast local static analysis using semgrep
- Git pre-commit hook integration
- Extension filtering and empty diff fast-path
