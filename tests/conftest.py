# ABOUTME: Pytest fixtures for meed test suite.
# ABOUTME: Provides test environment setup and SMTP mocking.

import sys
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from _pytest.monkeypatch import MonkeyPatch

from tests.test_utils import setup_test_env


@pytest.fixture(autouse=True)
def test_env(tmp_path: Path, monkeypatch: MonkeyPatch) -> Path:
    """Set up test environment with temporary directories and environment variables."""
    env_vars = setup_test_env(tmp_path)
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    # Force reload of meed module to pick up new environment variables
    if "meed" in sys.modules:
        del sys.modules["meed"]

    return tmp_path


@pytest.fixture
def mock_smtp() -> Generator[MagicMock, None, None]:
    """Mock smtplib.SMTP_SSL for email testing."""
    with patch("smtplib.SMTP_SSL") as mock:
        yield mock
