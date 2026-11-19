import json
import os
from email import message_from_string
from typing import TYPE_CHECKING, Any

import boto3

if TYPE_CHECKING:
    from pathlib import Path
    from unittest.mock import MagicMock


def create_feed_entry(
    entry_id: str | None,
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
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    return {
        "BUCKET_NAME": "meed-test",
        # The credentials of moto's fake S3, so that credentials in the developer's environment never reach a real
        # bucket.
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "MEED_SMTP_HOST": "smtp.test.com",
        "MEED_SMTP_PORT": "465",
        "MEED_SMTP_USER": "test@test.com",
        "MEED_SMTP_PASSWORD": "testpass",
        "MEED_EMAIL_FROM": "from@test.com",
        "MEED_EMAIL_TO": "to@test.com",
        # Empty, so that IMAP credentials in the developer's environment never reach a real mailbox. Tests of the
        # email-based feed addition set their own.
        "MEED_IMAP_HOST": "",
    }


def get_object(key: str) -> str | None:
    """The text of an object in the test bucket, or None when there is none."""
    client = boto3.client("s3")
    try:
        response = client.get_object(Bucket=os.environ["BUCKET_NAME"], Key=key)
    except client.exceptions.NoSuchKey:
        return None
    return response["Body"].read().decode()


def put_object(key: str, text: str) -> None:
    boto3.client("s3").put_object(Bucket=os.environ["BUCKET_NAME"], Key=key, Body=text.encode())


def delete_object(key: str) -> None:
    boto3.client("s3").delete_object(Bucket=os.environ["BUCKET_NAME"], Key=key)


def put_feeds(urls: list[str]) -> None:
    """Store a feed list with the given URLs."""
    put_object("feeds.txt", "\n".join(urls))


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
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    return int(sendmail_mock.call_count)


def stored_state() -> dict[str, list[str]]:
    """The state object meed stored, empty when there is none."""
    text = get_object("state.json")
    return json.loads(text) if text is not None else {}


def assert_seen_entries(feed_id: str, entry_ids: set[str]) -> None:
    """Assert that a feed is known and that exactly these of its entries are recorded as seen."""
    state = stored_state()
    assert feed_id in state, f"Feed {feed_id} not found in state"
    seen = state[feed_id]
    assert len(seen) == len(set(seen)), f"Seen entries {seen} repeat an ID"
    assert set(seen) == entry_ids, f"Expected seen entries {entry_ids}, got {seen}"


def get_email_body(email_str: str) -> str:
    """Extract and decode the body from an email string."""
    msg = message_from_string(email_str)
    payload = msg.get_payload(decode=True)
    if payload and isinstance(payload, bytes):
        return payload.decode("utf-8")
    return ""
