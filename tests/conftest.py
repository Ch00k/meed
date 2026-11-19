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
    """Answers a GET for each path with the status, body and headers a test gave it."""

    responses: dict[str, tuple[int, str, dict[str, str]]]


class FeedRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = self.server
        assert isinstance(server, FeedServer)
        status, body, headers = server.responses[self.path]

        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Keep requests out of the test output."""


@pytest.fixture
def serve_feed() -> Generator[Callable[..., str]]:
    """Serve responses over HTTP on localhost.

    serve_feed(status, body, headers=None) returns a URL of its own that answers with that response.
    """
    server = FeedServer(("127.0.0.1", 0), FeedRequestHandler)
    server.responses = {}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def serve(status: int, body: str, headers: dict[str, str] | None = None) -> str:
        path = f"/{len(server.responses)}.xml"
        server.responses[path] = (status, body, headers or {})
        return f"http://127.0.0.1:{server.server_port}{path}"

    yield serve

    server.shutdown()
    server.server_close()
