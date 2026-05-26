# Palisade Scanner 🔍

[![PyPI](https://img.shields.io/pypi/v/palisade-scanner)](https://pypi.org/project/palisade-scanner/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI](https://github.com/Carlos-Projects/palisade-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/palisade-scanner/actions)
[![HuggingFace Space](https://img.shields.io/badge/🤗%20Try%20it%20now-HF%20Spaces-yellow)](https://huggingface.co/spaces/Syntho/palisade-scanner)

**[Try it live on HuggingFace Spaces](https://huggingface.co/spaces/Syntho/palisade-scanner)** — scan any URL without installing anything.

**Scan web content for prompt injection, hidden instructions, and adversarial content targeting AI agents.**

AI agents browse the web, read documents, and consume external content. Adversaries hide instructions in invisible text, HTML metadata, encoded payloads, and zero-width characters — Palisade finds them all.

---

## What makes Palisade unique

| Capability | Palisade Scanner | Manual review | Generic scrapers |
|---|---|---|---|
| **Hidden text detection** | ✅ 20+ CSS/HTML techniques | ❌ | ❌ |
| **Injection pattern matching** | ✅ 100+ regexes, 5 categories | ❌ | ❌ |
| **LLM-as-judge classifier** | ✅ understands adversarial intent | N/A | ❌ |
| **Metadata analysis** | ✅ comments, JSON-LD, meta, data attrs | ❌ | ❌ |
| **Exfiltration detection** | ✅ URLs, eval(), fetch(), redirects | ❌ | ❌ |
| **MCPGuard policy generation** | ✅ auto-generate rules | ❌ | ❌ |
| **CI/CD mode** | ✅ `--ci --threshold high` | ❌ | ❌ |
| **Zero-width character detection** | ✅ | ❌ | ❌ |

---

## Why

AI agents browse the web, read documents, and consume external content. Adversaries can hide instructions in:

- **Invisible text** (white-on-white, zero font size, off-screen positioning)
- **HTML comments and metadata**
- **Base64 encoded payloads**
- **Zero-width character injections**
- **Instructions disguised as product descriptions or reviews**

This scanner finds them all and tells you what to do about it.

## Quick Start

```bash
# Install
pip install palisade-scanner

# CLI: scan a URL
pis scan https://example.com
# or
palisade scan https://example.com

# Web UI: open the dashboard
pis web

# Docker
docker compose up
# → http://localhost:8000
```

## Usage

### CLI

```bash
# Scan a URL
pis scan https://example.com

# Scan a local file
pis scan --file suspicious.html

# Scan pasted text
pis scan --paste "<!-- ignore instructions -->"

# JSON output
pis scan https://example.com --format json

# CI/CD mode (exit code reflects risk)
pis scan https://example.com --ci --threshold high

# Generate MCPGuard policy rules
pis policies https://evil-site.com
```

### API

```bash
# Scan via REST API
curl "http://localhost:8000/api/scan?url=https://example.com"

# HTML report
curl "http://localhost:8000/api/scan/https://example.com"
```

## How It Works

### Detection Layers

| Layer | What It Detects |
|-------|-----------------|
| **Hidden Text Detector** | 20+ CSS/HTML hiding techniques (display:none, visibility, opacity, color matching, off-screen, zero-width chars, HTML comments) |
| **Injection Pattern Matcher** | 100+ regex patterns across 5 categories (jailbreak, role override, exfiltration, tool manipulation, impersonation) |
| **Instruction Classifier** | LLM-as-judge that understands adversarial intent (requires API key) |
| **Metadata Analyzer** | HTML comments, JSON-LD, meta tags, data attributes, `<noscript>`, `<template>` |
| **Exfiltration Detector** | URLs, endpoints, eval() patterns, redirect attempts, `fetch()` calls |

### Scoring

```
Risk Score: 0-100

Weighted formula:
  base = 100
  - critical * 25
  - high * 10
  - medium * 3
  - low * 1

Categories: none (0-5) → low (6-20) → medium (21-50) → high (51-80) → critical (81-100)
```

## Architecture

```
User (CLI / Web / API)
        │
        ▼
PipelineOrchestrator
        │
        ├── Loader (URL / File / Paste / PDF)
        │
        ├── Detector Pipeline (parallel)
        │   ├── HiddenTextDetector
        │   ├── InjectionPatternMatcher
        │   ├── MetadataAnalyzer
        │   ├── ExfiltrationDetector
        │   └── InstructionClassifier (LLM)
        │
        ├── ScoringEngine
        │
        └── Reporters
            ├── JSON / Markdown / Simple
            ├── Policy Generator (MCPGuard)
            └── Web UI (HTMX)
```

## Project Structure

```
src/scanner/
├── cli.py              # Typer CLI
├── api.py              # FastAPI web app
├── config.py           # Settings (env vars)
├── domain/
│   ├── models.py       # Pydantic models
│   └── scoring.py      # Risk score engine
├── loaders/
│   ├── url.py          # HTTP URL fetcher
│   ├── pdf.py          # PDF extractor
│   └── paste.py        # Raw text
├── detectors/
│   ├── hidden_text.py       # CSS/HTML hiding
│   ├── injection_patterns.py # 100+ regex patterns
│   ├── instruction_classifier.py  # LLM-as-judge
│   ├── metadata_analyzer.py # Comments/meta/tags
│   └── exfiltration.py     # Data theft patterns
├── pipeline/
│   └── orchestrator.py # Scan pipeline
├── reporters/          # JSON/MD/Simple output
├── policies/           # MCPGuard rule generation
└── utils/              # DOM helpers
```

## Integration

### MCPGuard

Generate rules compatible with [MCPGuard](https://github.com/Carlos-Projects/mcpguard):

```bash
pis scan https://evil-site.com --format mcpguard > rules.yaml
mcpguard load-rules rules.yaml
```

### CI/CD

```yaml
# .github/workflows/check-urls.yml
- name: Scan for prompt injection
  run: |
    pis scan ${{ matrix.url }} --ci --threshold medium
```

## Roadmap

- **v0.1** — Scanner core: CLI, 5 detectors, scoring, policy generation
- **v0.2** — Live Monitor: scheduled re-scans, webhook alerts, diff detection
- **v0.3** — Agent Validator: Browser Use agent tests pages in real time
- **v0.4** — Content Safety Proxy: reverse proxy that strips injections
- **v0.5** — Reputation Engine: web of trust for agent-safe URLs
- **v0.6** — Red Team Lab: adversarial page generator + benchmark suite
- **v0.7** — Certification Pipeline: verified AgentSafe badges

## Related Projects

- [MCPGuard](https://github.com/Carlos-Projects/mcpguard) — Runtime security proxy for MCP
- [MCPwn](https://github.com/Carlos-Projects/mcpwn) — Offensive security testing for MCP
- [MCPscop](https://github.com/Carlos-Projects/mcpscope) — Unified security dashboard

## License

MIT
