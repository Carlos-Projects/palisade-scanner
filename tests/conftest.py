from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_adversarial_html():
    """Load a sample HTML file with hidden injections."""
    path = FIXTURES_DIR / "hidden_display_none.html"
    return path.read_text()


@pytest.fixture
def sample_clean_html():
    """Load a sample clean HTML file (no injections)."""
    path = FIXTURES_DIR / "clean_legit_page.html"
    return path.read_text()


@pytest.fixture
def sample_zero_width_html():
    """Load HTML with zero-width character injection."""
    path = FIXTURES_DIR / "zero_width_chars.html"
    return path.read_text()


@pytest.fixture
def sample_comment_injection_html():
    """Load HTML with injection in HTML comments."""
    path = FIXTURES_DIR / "instruction_in_comment.html"
    return path.read_text()


@pytest.fixture
def sample_exfiltration_html():
    """Load HTML with exfiltration patterns."""
    path = FIXTURES_DIR / "exfiltration_hidden.html"
    return path.read_text()
