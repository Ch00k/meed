# ABOUTME: Test utilities for generating RSS/Atom feeds, setting up test environments,
# ABOUTME: and providing assertion helpers for meed testing

import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock


def create_feed_entry(
    entry_id: str,
    title: str | None = None,
    summary: str | None = None,
    link: str | None = None,
    published: str | None = None,
    updated: str | None = None,
    created: str | None = None,
) -> dict[str, Any]:
    """Create a feed entry dictionary for RSS/Atom generation."""
    return {
        "id": entry_id,
        "title": title,
        "summary": summary,
        "link": link,
        "published": published,
        "updated": updated,
        "created": created,
    }


def create_rss_feed(
    entries: list[dict[str, Any]],
    feed_title: str | None = None,
    feed_id: str | None = None,
) -> str:
    """Create an RSS 2.0 XML feed string."""
    title = feed_title or "Test Feed"
    rss_id = feed_id or "http://example.com/feed"

    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0">',
        "<channel>",
        f"<title>{title}</title>",
        f"<link>{rss_id}</link>",
        "<description>Test feed description</description>",
    ]

    for entry in entries:
        xml_parts.append("<item>")

        if entry.get("id"):
            xml_parts.append(f"<guid>{entry['id']}</guid>")

        if entry.get("title"):
            xml_parts.append(f"<title>{entry['title']}</title>")

        if entry.get("link"):
            xml_parts.append(f"<link>{entry['link']}</link>")

        if entry.get("summary"):
            xml_parts.append(f"<description>{entry['summary']}</description>")

        if entry.get("published"):
            xml_parts.append(f"<pubDate>{entry['published']}</pubDate>")

        xml_parts.append("</item>")

    xml_parts.extend(["</channel>", "</rss>"])
    return "\n".join(xml_parts)


def create_atom_feed(
    entries: list[dict[str, Any]],
    feed_title: str | None = None,
    feed_id: str | None = None,
) -> str:
    """Create an Atom 1.0 XML feed string."""
    title = feed_title or "Test Feed"
    atom_id = feed_id or "http://example.com/feed"

    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<feed xmlns="http://www.w3.org/2005/Atom">',
        f"<title>{title}</title>",
        f"<id>{atom_id}</id>",
        "<updated>2025-01-01T00:00:00Z</updated>",
    ]

    for entry in entries:
        xml_parts.append("<entry>")

        if entry.get("id"):
            xml_parts.append(f"<id>{entry['id']}</id>")

        if entry.get("title"):
            xml_parts.append(f"<title>{entry['title']}</title>")

        if entry.get("link"):
            xml_parts.append(f'<link href="{entry["link"]}"/>')

        if entry.get("summary"):
            xml_parts.append(f"<summary>{entry['summary']}</summary>")

        if entry.get("published"):
            xml_parts.append(f"<published>{entry['published']}</published>")

        if entry.get("updated"):
            xml_parts.append(f"<updated>{entry['updated']}</updated>")

        if entry.get("created"):
            xml_parts.append(f'<created xmlns="http://purl.org/dc/terms/">{entry["created"]}</created>')

        xml_parts.append("</entry>")

    xml_parts.append("</feed>")
    return "\n".join(xml_parts)


def setup_test_env(tmp_path: Path) -> dict[str, str]:
    """Set up test environment directories and return environment variables."""
    feeds_file = tmp_path / "feeds.txt"
    state_db = tmp_path / "state.db"
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    feeds_file.write_text("")

    return {
        "MEED_FEEDS_FILE_PATH": str(feeds_file),
        "MEED_STATE_DB_PATH": str(state_db),
        "MEED_SMTP_HOST": "smtp.test.com",
        "MEED_SMTP_PORT": "465",
        "MEED_SMTP_USER": "test@test.com",
        "MEED_SMTP_PASSWORD": "testpass",
        "MEED_EMAIL_FROM": "from@test.com",
        "MEED_EMAIL_TO": "to@test.com",
    }


def create_feeds_file(urls: list[str], path: Path) -> Path:
    """Create a feeds.txt file with the given URLs."""
    path.write_text("\n".join(urls))
    return path


def assert_email_sent(
    mock_smtp: MagicMock,
    subject: str,
    from_addr: str,
    to_addr: str,
    body_contains: str | None = None,
) -> None:
    """Assert that an email was sent with the given parameters."""
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    sendmail_mock.assert_called()

    found = False
    for call in sendmail_mock.call_args_list:
        args = call[0]
        sent_from = args[0]
        sent_to = args[1]
        message_str = args[2]

        if (
            subject in message_str
            and sent_from == from_addr
            and sent_to == to_addr
            and (body_contains is None or body_contains in message_str)
        ):
            found = True
            break

    assert found, f"No email found with subject='{subject}', from='{from_addr}', to='{to_addr}'"


def assert_no_emails_sent(mock_smtp: MagicMock) -> None:
    """Assert that no emails were sent."""
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    sendmail_mock.assert_not_called()


def get_email_count(mock_smtp: MagicMock) -> int:
    """Get the number of emails sent."""
    if not mock_smtp.called:
        return 0
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    return int(sendmail_mock.call_count)


def query_db(db_path: Path, query: str, params: tuple = ()) -> list:
    """Execute a SQL query and return all results."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return rows


def assert_feed_state(db_path: Path, feed_id: str, last_entry_id: str) -> None:
    """Assert that a feed has the expected state in the database."""
    rows = query_db(db_path, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_id,))
    assert len(rows) > 0, f"Feed {feed_id} not found in database"
    assert rows[0][0] == last_entry_id, f"Expected last_entry_id={last_entry_id}, got {rows[0][0]}"
