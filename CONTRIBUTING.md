# Contributing

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
