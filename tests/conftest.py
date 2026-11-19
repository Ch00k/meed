# ABOUTME: Pytest fixtures for meed test suite.
# ABOUTME: Provides test environment setup, SMTP mocking and a local HTTP server for feeds.

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from tests.test_utils import setup_test_env

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from _pytest.monkeypatch import MonkeyPatch


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
def mock_smtp() -> Generator[MagicMock]:
    """Mock smtplib.SMTP_SSL for email testing."""
    with patch("smtplib.SMTP_SSL") as mock:
        yield mock


class FeedServer(ThreadingHTTPServer):
    """Answers every GET with the status and body a test gave it."""

    status = 200
    body = ""


class FeedRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = self.server
        assert isinstance(server, FeedServer)

        self.send_response(server.status)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(server.body.encode())

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Keep requests out of the test output."""


@pytest.fixture
def serve_feed() -> Generator[Callable[[int, str], str]]:
    """Serve a response over HTTP on localhost: serve_feed(status, body) returns the URL that answers with it."""
    server = FeedServer(("127.0.0.1", 0), FeedRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def serve(status: int, body: str) -> str:
        server.status = status
        server.body = body
        return f"http://127.0.0.1:{server.server_port}/feed.xml"

    yield serve

    server.shutdown()
    server.server_close()
