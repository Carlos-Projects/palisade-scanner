# Contributing to Palisade Scanner

👋 **Welcome to Palisade Scanner!**

Thank you for stopping by and considering contributing. Whether you're improving prompt injection detection, squashing bugs, or writing docs — you're helping make the web a safer place for AI interactions. We appreciate you!

## First Time Contributor?

New to open source or security scanning? Here's how to get your feet wet:

- Look for `good first issue` or `help wanted` labels
- Add a new detector — our detector interface is simple and well-documented
- Improve test coverage or fix a typo in the docs
- Join the conversation on existing issues — your perspective matters

## Need Help?

Run into a problem or have a question?

- Open a [GitHub Issue](https://github.com/Carlos-Projects/palisade-scanner/issues)
- Search existing issues first — someone might have answered it
- Share details: what you tried, what happened, and what you expected

## Development Setup

```bash
git clone https://github.com/Carlos-Projects/palisade-scanner.git
cd palisade-scanner
pip install -e ".[dev]"
```

## Workflow

1. Create a branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Run checks: `ruff check . && python -m pytest tests/ -v`
4. Add tests for new functionality
5. Commit: `git commit -m "type(scope): description"`
6. Push and open a PR

## Quality Gates

Before submitting a PR, ensure:

- `ruff check .` — passes
- `python -m pytest tests/ -v` — all tests pass
- Tests added for new features

## Code Style

- Line length: 120
- Ruff enforces imports, naming, and formatting
- Type hints required for all public functions

## Pull Request Process

1. Use the PR template
2. Keep PRs focused on a single change
3. Reference related issues
4. Squash commits before merging

---

💡 This project is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its principles.
