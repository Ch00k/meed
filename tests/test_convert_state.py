import json
import sqlite3
from typing import TYPE_CHECKING

from scripts.convert_state import convert, main
from tests.test_utils import assert_no_emails_sent, create_feed_entry, create_rss_feed, put_feeds, put_object

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock

    import pytest

# Nothing listens on port 1, so fetching a feed there fails.
UNREACHABLE_FEED = "http://127.0.0.1:1/feed.xml"


def _entry(name: str, hour: int) -> dict:
    """An RSS entry named name, dated on 1 January 2025 at hour."""
    return create_feed_entry(
        f"http://example.com/{name}",
        f"Entry {name}",
        f"Summary {name}",
        f"http://example.com/{name}",
        f"Mon, 01 Jan 2025 {hour:02d}:00:00 GMT",
    )


def _write_db(db_path: Path, feeds: list[tuple[str, str | None]], seen: list[tuple[str, str]] | None = None) -> None:
    """Write a state database: a feeds table of (id, last_entry_id), and, unless seen is None, a seen_entries table."""
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE feeds (id TEXT, last_checked_at DATETIME, last_entry_id TEXT)")
    conn.executemany("INSERT INTO feeds VALUES (?, datetime('now'), ?)", feeds)
    if seen is not None:
        conn.execute("CREATE TABLE seen_entries (feed_id TEXT NOT NULL, entry_id TEXT NOT NULL)")
        conn.executemany("INSERT INTO seen_entries VALUES (?, ?)", seen)
    conn.commit()
    conn.close()


def _sent_subjects(mock_smtp: MagicMock) -> list[str]:
    """The Subject header of every email sent, in the order they were sent."""
    from email import message_from_string

    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    return [message_from_string(call.args[2])["Subject"] for call in sendmail_mock.call_args_list]


def _run_meed_on(state: dict[str, set[str]], feed_urls: list[str]) -> None:
    """Store the converted state and the feed list in the bucket, and run meed once."""
    from meed import format_state, main

    put_object("state.json", format_state(state))
    put_feeds(feed_urls)
    main()


def test_last_entry_id_becomes_seen_entries(test_env: Path, mock_smtp: MagicMock) -> None:
    """A feed's last entry ID, and every entry the feed lists after it, become its seen entries.

    The entries listed before it are new: meed, run on the converted state, sends them oldest first, and once only.
    """
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed([_entry("D", 13), _entry("C", 12), _entry("B", 11), _entry("A", 10)]))
    feed_url = f"file://{feed_file}"
    db_path = test_env / "state.db"
    _write_db(db_path, [(feed_url, "http://example.com/B")])

    state = convert(db_path)

    assert state == {feed_url: {"http://example.com/A", "http://example.com/B"}}

    _run_meed_on(state, [feed_url])

    assert _sent_subjects(mock_smtp) == ["Entry C", "Entry D"]

    mock_smtp.reset_mock()
    from meed import main

    main()

    assert_no_emails_sent(mock_smtp)


def test_last_entry_id_that_left_the_feed(
    test_env: Path, mock_smtp: MagicMock, capsys: pytest.CaptureFixture[str]
) -> None:
    """When the last entry is no longer in the feed, which entries are new cannot be told: all of them count as seen.

    The last entry itself is seen too, so it is not sent when the feed lists it again.
    """
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed([_entry("C", 12), _entry("B", 11)]))
    feed_url = f"file://{feed_file}"
    db_path = test_env / "state.db"
    _write_db(db_path, [(feed_url, "http://example.com/A")])

    state = convert(db_path)

    assert state == {feed_url: {"http://example.com/A", "http://example.com/B", "http://example.com/C"}}
    assert f"Last sent entry http://example.com/A is no longer in feed {feed_url}\n" in capsys.readouterr().err

    feed_file.write_text(create_rss_feed([_entry("C", 12), _entry("B", 11), _entry("A", 10)]))
    _run_meed_on(state, [feed_url])

    assert_no_emails_sent(mock_smtp)


def test_feed_without_a_last_entry_id(test_env: Path, mock_smtp: MagicMock) -> None:
    """A feed that was empty when first checked has no last entry ID: it is known, and every entry it has is new."""
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed([_entry("B", 11), _entry("A", 10)]))
    feed_url = f"file://{feed_file}"
    db_path = test_env / "state.db"
    _write_db(db_path, [(feed_url, None)])

    state = convert(db_path)

    assert state == {feed_url: set()}

    _run_meed_on(state, [feed_url])

    assert _sent_subjects(mock_smtp) == ["Entry A", "Entry B"]


def test_seen_entries_are_kept(test_env: Path) -> None:
    """A feed with seen entries keeps exactly those, and is not fetched; one without them goes by its last entry ID.

    The feed with seen entries is unreachable, so fetching it would leave it out.
    """
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed([_entry("2", 11), _entry("1", 10)]))
    feed_url = f"file://{feed_file}"
    db_path = test_env / "state.db"
    _write_db(
        db_path,
        [(UNREACHABLE_FEED, "http://example.com/x2"), (feed_url, "http://example.com/2")],
        [(UNREACHABLE_FEED, "http://example.com/x1"), (UNREACHABLE_FEED, "http://example.com/x2")],
    )

    assert convert(db_path) == {
        UNREACHABLE_FEED: {"http://example.com/x1", "http://example.com/x2"},
        feed_url: {"http://example.com/1", "http://example.com/2"},
    }


def test_feed_that_cannot_be_fetched_is_left_out(test_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A feed whose last entry ID needs its entries, and that cannot be fetched, is left out with a message.

    Left out, it is new to meed, whose first check of it records its entries and sends none.
    """
    db_path = test_env / "state.db"
    _write_db(db_path, [(UNREACHABLE_FEED, "http://example.com/1"), ("http://example.com/empty", None)])

    assert convert(db_path) == {"http://example.com/empty": set()}
    assert f"Leaving out feed {UNREACHABLE_FEED}, which cannot be fetched: " in capsys.readouterr().err


def test_main_writes_the_state_object(test_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """main() converts the database named first into the JSON file named second, which meed reads as its state."""
    from meed import read_state

    db_path = test_env / "state.db"
    json_path = test_env / "state.json"
    _write_db(
        db_path,
        [("http://example.com/feed", None)],
        [("http://example.com/feed", "b"), ("http://example.com/feed", "a")],
    )
    monkeypatch.setattr("sys.argv", ["convert_state", str(db_path), str(json_path)])

    main()

    assert json.loads(json_path.read_text()) == {"http://example.com/feed": ["a", "b"]}

    put_object("state.json", json_path.read_text())

    assert read_state() == {"http://example.com/feed": {"a", "b"}}


def test_last_entry_id_of_an_entry_identified_by_its_title(test_env: Path, mock_smtp: MagicMock) -> None:
    """An entry with neither an ID nor a link, which meed 0.3.0 identified by its bare title, is found by that title.

    Its ID and those of the entries listed after it are recorded as meed identifies them, by title and date, so meed
    sends only the entry listed before it.
    """

    def titled(name: str, hour: int) -> dict:
        return create_feed_entry(
            None, f"Post {name}", f"Summary {name}", None, f"Mon, 01 Jan 2025 {hour:02d}:00:00 GMT"
        )

    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed([titled("C", 12), titled("B", 11), titled("A", 10)]))
    feed_url = f"file://{feed_file}"
    db_path = test_env / "state.db"
    _write_db(db_path, [(feed_url, "Post B")])

    state = convert(db_path)

    assert state == {feed_url: {"Post A 2025-01-01T10:00:00Z", "Post B 2025-01-01T11:00:00Z"}}

    _run_meed_on(state, [feed_url])

    assert _sent_subjects(mock_smtp) == ["Post C"]


def test_main_sets_network_timeout(test_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """main() bounds every feed fetch, so a feed that stalls is left out like one that cannot be fetched."""
    import socket

    from meed import NETWORK_TIMEOUT

    db_path = test_env / "state.db"
    _write_db(db_path, [])
    monkeypatch.setattr("sys.argv", ["convert_state", str(db_path), str(test_env / "state.json")])

    try:
        main()
        assert socket.getdefaulttimeout() == NETWORK_TIMEOUT
    finally:
        socket.setdefaulttimeout(None)
