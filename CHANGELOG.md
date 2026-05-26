# Palisade Scanner

## [Unreleased]

### Fixed
- Path traversal vulnerability in file-based scan results
- Async parallelization for multi-page scanning

### Added
- Playwright-based JavaScript-rendered page scanning
- LLM-based instruction classifier detector
- PDF report generation via WeasyPrint
- Scheduled/cron scanning via APScheduler

## [0.1.0] - 2025-08-01

### Added
- Initial scanner implementation
- Hidden text detection (invisible/zero-width characters, display:none)
- Injection pattern detection (regex-based)
- Metadata analysis detector
- Exfiltration detector (suspicious data flows)
- MCPGuard policy generation from scan results
- HTMX web UI with scan management
- REST API endpoints
- Typer CLI entry point (`pis` command)
