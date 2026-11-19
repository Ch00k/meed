# ABOUTME: Comprehensive test suite for meed RSS/Atom feed email notification system.
# ABOUTME: Tests cover feed processing, entry validation, email sending, and error handling.

import os
from pathlib import Path
from typing import TYPE_CHECKING

from tests.test_utils import (
    assert_feed_state,
    assert_no_emails_sent,
    create_atom_feed,
    create_feed_entry,
    create_feeds_file,
    create_rss_feed,
    get_email_body,
    get_email_count,
    query_db,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from unittest.mock import MagicMock

    import pytest


def test_new_feed_no_emails_sent(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 1: First run of a new feed should not send emails, only create state."""
    from meed import main

    # Create RSS feed with 3 entries (using absolute URLs like production)
    entries = [
        create_feed_entry(
            "http://example.com/entry-1",
            "Entry 1",
            "Summary 1",
            "http://example.com/1",
            "Mon, 01 Jan 2025 10:00:00 GMT",
        ),
        create_feed_entry(
            "http://example.com/entry-2",
            "Entry 2",
            "Summary 2",
            "http://example.com/2",
            "Mon, 01 Jan 2025 11:00:00 GMT",
        ),
        create_feed_entry(
            "http://example.com/entry-3",
            "Entry 3",
            "Summary 3",
            "http://example.com/3",
            "Mon, 01 Jan 2025 12:00:00 GMT",
        ),
    ]
    feed_xml = create_rss_feed(entries)
    feed_file = test_env / "data" / "feed1.xml"
    feed_file.write_text(feed_xml)

    # Create feeds file pointing to local file
    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Run meed once
    main()

    # Assert no emails sent
    assert_no_emails_sent(mock_smtp)

    # Assert database state created with latest entry
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    assert len(rows) > 0, "Feed not found in database"
    assert rows[0][0] == "http://example.com/entry-3"

    # Assert last_checked_at is set
    rows = query_db(state_db, "SELECT last_checked_at FROM feeds WHERE id = ?", (feed_url,))
    assert len(rows) > 0
    assert rows[0][0] is not None


def test_new_entries_notification(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 2: New entries trigger email notifications in chronological order."""
    from meed import main

    # Create initial feed with 3 entries (A, B, C - oldest to newest)
    initial_entries = [
        create_feed_entry(
            "http://example.com/entry-a",
            "Entry A",
            "Summary A",
            "http://example.com/a",
            "Mon, 01 Jan 2025 10:00:00 GMT",
        ),
        create_feed_entry(
            "http://example.com/entry-b",
            "Entry B",
            "Summary B",
            "http://example.com/b",
            "Mon, 01 Jan 2025 11:00:00 GMT",
        ),
        create_feed_entry(
            "http://example.com/entry-c",
            "Entry C",
            "Summary C",
            "http://example.com/c",
            "Mon, 01 Jan 2025 12:00:00 GMT",
        ),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Run once to establish baseline
    main()
    assert_no_emails_sent(mock_smtp)

    # Add 2 new entries (D, E)
    new_entries = [
        *initial_entries,
        create_feed_entry(
            "http://example.com/entry-d",
            "Entry D",
            "Summary D",
            "http://example.com/d",
            "Mon, 01 Jan 2025 13:00:00 GMT",
        ),
        create_feed_entry(
            "http://example.com/entry-e",
            "Entry E",
            "Summary E",
            "http://example.com/e",
            "Mon, 01 Jan 2025 14:00:00 GMT",
        ),
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    # Run again
    mock_smtp.reset_mock()
    main()

    # Assert 2 emails sent
    from tests.test_utils import get_email_count

    assert get_email_count(mock_smtp) == 2

    # Check emails sent in chronological order (D first, then E)
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    calls = sendmail_mock.call_args_list
    assert len(calls) == 2

    # First email should be Entry D
    first_email_body = get_email_body(calls[0][0][2])
    assert "Entry D" in calls[0][0][2]  # Subject in headers
    assert "Summary D" in first_email_body

    # Second email should be Entry E
    second_email_body = get_email_body(calls[1][0][2])
    assert "Entry E" in calls[1][0][2]  # Subject in headers
    assert "Summary E" in second_email_body

    # Assert database updated with newest entry
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    assert rows[0][0] == "http://example.com/entry-e"


def test_no_new_entries(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 3: No action when feed hasn't changed."""
    from meed import main

    entries = [
        create_feed_entry(
            "http://example.com/entry-1",
            "Entry 1",
            "Summary 1",
            "http://example.com/1",
            "Mon, 01 Jan 2025 10:00:00 GMT",
        ),
        create_feed_entry(
            "http://example.com/entry-2",
            "Entry 2",
            "Summary 2",
            "http://example.com/2",
            "Mon, 01 Jan 2025 11:00:00 GMT",
        ),
        create_feed_entry(
            "http://example.com/entry-3",
            "Entry 3",
            "Summary 3",
            "http://example.com/3",
            "Mon, 01 Jan 2025 12:00:00 GMT",
        ),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Run once to establish baseline
    main()
    assert_no_emails_sent(mock_smtp)

    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    initial_state = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    initial_checked = query_db(state_db, "SELECT last_checked_at FROM feeds WHERE id = ?", (feed_url,))

    # Run again without modifying feed
    mock_smtp.reset_mock()
    main()

    # No emails sent
    assert_no_emails_sent(mock_smtp)

    # Database state unchanged (except last_checked_at)
    new_state = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    assert new_state[0][0] == initial_state[0][0]

    # last_checked_at updated
    new_checked = query_db(state_db, "SELECT last_checked_at FROM feeds WHERE id = ?", (feed_url,))
    assert new_checked[0][0] >= initial_checked[0][0]


def test_multiple_feeds(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 4: Multiple feeds handled independently."""
    from meed import main

    # Create two feeds
    feed1_entries = [
        create_feed_entry(
            "http://feed1.com/1", "Feed1 Entry1", "Summary1", "http://feed1.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        ),
        create_feed_entry(
            "http://feed1.com/2", "Feed1 Entry2", "Summary2", "http://feed1.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
    ]
    feed2_entries = [
        create_feed_entry(
            "http://feed2.com/1", "Feed2 Entry1", "Summary1", "http://feed2.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        ),
        create_feed_entry(
            "http://feed2.com/2", "Feed2 Entry2", "Summary2", "http://feed2.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
    ]

    feed1_file = test_env / "data" / "feed1.xml"
    feed2_file = test_env / "data" / "feed2.xml"
    feed1_file.write_text(create_rss_feed(feed1_entries))
    feed2_file.write_text(create_rss_feed(feed2_entries))

    feed1_url = f"file://{feed1_file}"
    feed2_url = f"file://{feed2_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed1_url, feed2_url], feeds_file)

    # Establish baseline
    main()
    assert_no_emails_sent(mock_smtp)

    # Verify both feeds in database
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows1 = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed1_url,))
    rows2 = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed2_url,))
    assert len(rows1) > 0
    assert len(rows2) > 0

    # Add entry to feed1 only
    feed1_entries.append(
        create_feed_entry(
            "http://feed1.com/3", "Feed1 Entry3", "Summary3", "http://feed1.com/3", "Mon, 01 Jan 2025 12:00:00 GMT"
        )
    )
    feed1_file.write_text(create_rss_feed(feed1_entries))

    mock_smtp.reset_mock()
    main()

    # Only 1 email sent (from feed1)
    from tests.test_utils import get_email_count

    assert get_email_count(mock_smtp) == 1

    # Verify only feed1 state updated
    new_rows1 = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed1_url,))
    new_rows2 = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed2_url,))
    assert new_rows1[0][0] == "http://feed1.com/3"
    assert new_rows2[0][0] == rows2[0][0]  # Unchanged


def test_entry_without_id(test_env: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Test 5: Entry without ID uses link as fallback."""
    from meed import main

    # Create feed with entry missing id field
    entries = [
        create_feed_entry(None, "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Run once
    main()

    # Check warning logged
    assert any("has no id" in record.message.lower() for record in caplog.records)

    # Verify state uses link as ID
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    assert rows[0][0] == "http://example.com/1"


def test_entry_without_title(test_env: Path, mock_smtp: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    """Test 6: Entry without title uses ID as fallback."""
    from meed import main

    initial_entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        ),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()

    # Add entry without title
    new_entries = [
        *initial_entries,
        create_feed_entry(
            "http://example.com/2", None, "Summary 2", "http://example.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    mock_smtp.reset_mock()
    caplog.clear()
    main()

    # Warning logged
    assert any("has no title" in record.message.lower() for record in caplog.records)

    # Email sent with ID as subject
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    assert sendmail_mock.call_count == 1
    email_str = sendmail_mock.call_args[0][2]
    assert "http://example.com/2" in email_str  # ID as subject


def test_entry_without_summary(test_env: Path, mock_smtp: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    """Test 7: Entry without summary uses ID as fallback."""
    from meed import main

    initial_entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        ),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    main()

    # Add entry without summary
    new_entries = [
        *initial_entries,
        create_feed_entry(
            "http://example.com/2", "Entry 2", None, "http://example.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    mock_smtp.reset_mock()
    caplog.clear()
    main()

    # Warning logged
    assert any("has no summary" in record.message.lower() for record in caplog.records)

    # Email sent with ID as body
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    assert sendmail_mock.call_count == 1


def test_entry_without_published_date(test_env: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Test 8: Entry without date fields is skipped."""
    from meed import main

    entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        ),
        create_feed_entry("http://example.com/2", "Entry 2", "Summary 2", "http://example.com/2", None),  # No date
        create_feed_entry(
            "http://example.com/3", "Entry 3", "Summary 3", "http://example.com/3", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    main()

    # Warning logged about missing date
    assert any("has no published date" in record.message.lower() for record in caplog.records)

    # Other valid entries processed
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    assert len(rows) > 0


def test_entry_with_multiple_date_fields(test_env: Path) -> None:
    """Test 9: Entry with multiple date fields uses published field."""
    from meed import main

    # For Atom feed, use updated/published
    entries = [
        {
            "id": "http://example.com/1",
            "title": "Entry 1",
            "summary": "Summary 1",
            "link": "http://example.com/1",
            "published": "2025-01-01T10:00:00Z",
            "updated": "2025-01-01T15:00:00Z",
            "created": "2025-01-01T09:00:00Z",
        },
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_atom_feed(entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    main()

    # Entry processed successfully
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    assert rows[0][0] == "http://example.com/1"


def test_atom_feed_processing(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 10: Atom feed format is processed correctly."""
    from meed import main

    initial_entries = [
        {
            "id": "http://example.com/1",
            "title": "Entry 1",
            "summary": "Summary 1",
            "link": "http://example.com/1",
            "published": "2025-01-01T10:00:00Z",
        },
        {
            "id": "http://example.com/2",
            "title": "Entry 2",
            "summary": "Summary 2",
            "link": "http://example.com/2",
            "published": "2025-01-01T11:00:00Z",
        },
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_atom_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()
    assert_no_emails_sent(mock_smtp)

    # Add new entry
    new_entries = [
        *initial_entries,
        {
            "id": "http://example.com/3",
            "title": "Entry 3",
            "summary": "Summary 3",
            "link": "http://example.com/3",
            "published": "2025-01-01T12:00:00Z",
        },
    ]
    feed_file.write_text(create_atom_feed(new_entries))

    mock_smtp.reset_mock()
    main()

    # Email sent for new entry
    assert get_email_count(mock_smtp) == 1
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    email_str = sendmail_mock.call_args[0][2]
    assert "Entry 3" in email_str  # Subject in headers


def test_feed_without_metadata(test_env: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Test 11: Feed without title uses URL as fallback."""
    from meed import main

    # Create RSS without feed title
    entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    xml = create_rss_feed(entries, feed_title=None)
    # Remove the title tag
    xml = xml.replace("<title>Test Feed</title>", "")

    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(xml)

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    main()

    # Warning logged
    assert any("title" in record.message.lower() for record in caplog.records)

    # Processing continues
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    assert len(rows) > 0


def test_malformed_feed_url(test_env: Path) -> None:
    """Test 12: Invalid feed URL doesn't crash (feedparser is forgiving)."""
    from meed import main

    # Add invalid and valid URLs
    valid_entries = [
        create_feed_entry(
            "http://valid.com/1", "Entry 1", "Summary 1", "http://valid.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    valid_file = test_env / "data" / "valid.xml"
    valid_file.write_text(create_rss_feed(valid_entries))

    valid_url = f"file://{valid_file}"
    invalid_url = "not-a-valid-url"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([invalid_url, valid_url], feeds_file)

    # Should not crash (feedparser handles invalid URLs gracefully)
    main()

    # Valid feed still processed
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (valid_url,))
    assert len(rows) > 0


def test_network_error_simulation(test_env: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Test 13: Network errors are logged but don't crash."""
    from unittest.mock import patch

    from meed import main

    # Create valid feed for other processing
    valid_entries = [
        create_feed_entry(
            "http://valid.com/1", "Entry 1", "Summary 1", "http://valid.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    valid_file = test_env / "data" / "valid.xml"
    valid_file.write_text(create_rss_feed(valid_entries))

    valid_url = f"file://{valid_file}"
    failing_url = "http://failing.example.com/feed"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([failing_url, valid_url], feeds_file)

    # Mock feedparser to raise exception for failing URL
    import feedparser

    original_parse = feedparser.parse

    def mock_parse(url: str, **kwargs: object) -> feedparser.FeedParserDict:
        if "failing" in url:
            raise ConnectionError("Network error")
        return original_parse(url, **kwargs)

    with patch("feedparser.parse", side_effect=mock_parse):
        main()

    # Error logged
    assert any("error" in record.message.lower() for record in caplog.records)

    # Valid feed still processed
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (valid_url,))
    assert len(rows) > 0


def test_smtp_error_handling(test_env: Path, mock_smtp: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    """Test 14: SMTP errors are logged and state not updated."""
    from meed import main

    initial_entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()

    # Add new entry
    new_entries = [
        *initial_entries,
        create_feed_entry(
            "http://example.com/2", "Entry 2", "Summary 2", "http://example.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    # Make SMTP raise exception
    mock_smtp.return_value.__enter__.return_value.sendmail.side_effect = Exception("SMTP failed")

    caplog.clear()
    mock_smtp.reset_mock()

    # Should not crash
    main()

    # Error logged
    assert any("error" in record.message.lower() for record in caplog.records)

    # Database state should not be updated (transaction rolled back)
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    assert rows[0][0] == "http://example.com/1"  # Still old entry


def test_entry_order_preservation(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 15: Entries sent in chronological order (oldest first)."""
    from meed import main

    initial_entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()

    # Add 3 new entries in non-chronological order in XML
    new_entries = [
        *initial_entries,
        create_feed_entry(
            "http://example.com/4", "Entry 4", "Summary 4", "http://example.com/4", "Mon, 01 Jan 2025 13:00:00 GMT"
        ),  # Newest
        create_feed_entry(
            "http://example.com/2", "Entry 2", "Summary 2", "http://example.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),  # Oldest new
        create_feed_entry(
            "http://example.com/3", "Entry 3", "Summary 3", "http://example.com/3", "Mon, 01 Jan 2025 12:00:00 GMT"
        ),  # Middle
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    mock_smtp.reset_mock()
    main()

    # 3 emails sent
    assert get_email_count(mock_smtp) == 3

    # Check order: oldest to newest (2, 3, 4)
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    calls = sendmail_mock.call_args_list

    # Check subjects in headers
    assert "Entry 2" in calls[0][0][2]
    assert "Entry 3" in calls[1][0][2]
    assert "Entry 4" in calls[2][0][2]


def test_empty_feeds_file(mock_smtp: MagicMock) -> None:
    """Test 16: Empty feeds file is handled gracefully."""
    from meed import main

    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    feeds_file.write_text("")

    # Should not crash
    main()

    # No emails sent
    assert_no_emails_sent(mock_smtp)


def test_comments_in_feeds_file(test_env: Path) -> None:
    """Test 17: Comments in feeds file are ignored."""
    from meed import main

    entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    feeds_file.write_text(f"# This is a comment\n{feed_url}\n# Another comment")

    # Should process only valid URL
    main()

    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    assert len(rows) > 0


def test_duplicate_entries_in_feed(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 18: Duplicate entry IDs are handled correctly."""
    from meed import main

    initial_entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        ),
        create_feed_entry(
            "http://example.com/2", "Entry 2", "Summary 2", "http://example.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()

    # Add duplicate and new entry
    new_entries = [
        *initial_entries,
        create_feed_entry(
            "http://example.com/2",
            "Entry 2 Duplicate",
            "Duplicate",
            "http://example.com/2",
            "Mon, 01 Jan 2025 11:00:00 GMT",
        ),
        create_feed_entry(
            "http://example.com/3", "Entry 3", "Summary 3", "http://example.com/3", "Mon, 01 Jan 2025 12:00:00 GMT"
        ),
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    mock_smtp.reset_mock()
    main()

    # Only 1 email sent (for genuinely new entry)
    assert get_email_count(mock_smtp) == 1
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    email_str = sendmail_mock.call_args[0][2]
    assert "Entry 3" in email_str


def test_very_old_entry_added(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 19: Old entry added after newer ones is not detected as new."""
    from meed import main

    initial_entries = [
        create_feed_entry(
            "http://example.com/a", "Entry A", "Summary A", "http://example.com/a", "Mon, 01 Jan 2025 10:00:00 GMT"
        ),
        create_feed_entry(
            "http://example.com/b", "Entry B", "Summary B", "http://example.com/b", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
        create_feed_entry(
            "http://example.com/c", "Entry C", "Summary C", "http://example.com/c", "Mon, 01 Jan 2025 12:00:00 GMT"
        ),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline (C is latest)
    main()

    # Insert entry D between A and B (older than C)
    new_entries = [
        initial_entries[0],  # A
        create_feed_entry(
            "http://example.com/d", "Entry D", "Summary D", "http://example.com/d", "Mon, 01 Jan 2025 10:30:00 GMT"
        ),  # Between A and B
        initial_entries[1],  # B
        initial_entries[2],  # C
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    mock_smtp.reset_mock()
    main()

    # No email sent (D is older than last known entry C)
    assert_no_emails_sent(mock_smtp)


def test_all_entries_removed_then_readded(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 20: Feed cleared and repopulated treats all as new."""
    from meed import main

    initial_entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        ),
        create_feed_entry(
            "http://example.com/2", "Entry 2", "Summary 2", "http://example.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
        create_feed_entry(
            "http://example.com/3", "Entry 3", "Summary 3", "http://example.com/3", "Mon, 01 Jan 2025 12:00:00 GMT"
        ),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()

    # Clear feed entries
    feed_file.write_text(create_rss_feed([]))

    mock_smtp.reset_mock()
    main()

    # No emails sent
    assert_no_emails_sent(mock_smtp)

    # Re-add original entries plus new one
    new_entries = [
        *initial_entries,
        create_feed_entry(
            "http://example.com/4", "Entry 4", "Summary 4", "http://example.com/4", "Mon, 01 Jan 2025 13:00:00 GMT"
        ),
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    mock_smtp.reset_mock()
    main()

    # Only entry 4 is new (entry-3 is still the last known entry)
    assert get_email_count(mock_smtp) == 1


def test_state_database_corruption(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 21: Corrupted database is recreated."""
    from meed import main

    entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        ),
        create_feed_entry(
            "http://example.com/2", "Entry 2", "Summary 2", "http://example.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()

    # Delete database
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    state_db.unlink()

    mock_smtp.reset_mock()
    # Should recreate database
    main()

    # Feed treated as new (no emails)
    assert_no_emails_sent(mock_smtp)

    # Database recreated
    assert state_db.exists()


def test_unicode_content(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 22: Unicode content is handled correctly."""
    from meed import main

    initial_entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()

    # Add entry with unicode
    unicode_title = "Entry with emoji 🎉 and Chinese 中文"
    unicode_summary = "Summary with emoji 🚀 and more unicode ñ ü"
    new_entries = [
        *initial_entries,
        create_feed_entry(
            "http://example.com/2",
            unicode_title,
            unicode_summary,
            "http://example.com/2",
            "Mon, 01 Jan 2025 11:00:00 GMT",
        ),
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    mock_smtp.reset_mock()
    main()

    # Email sent
    assert get_email_count(mock_smtp) == 1
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    email_str = sendmail_mock.call_args[0][2]
    email_body = get_email_body(email_str)

    # Unicode preserved
    assert "utf-8" in email_str.lower()  # Charset in headers
    assert "中文" in email_body or "emoji" in email_body or "🎉" in email_body


def test_html_in_summary(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 23: HTML in summary is preserved."""
    from meed import main

    initial_entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()

    # Add entry with HTML
    html_summary = "<p>This is <strong>bold</strong> and <em>italic</em> text.</p><a href='http://example.com'>Link</a>"
    new_entries = [
        *initial_entries,
        create_feed_entry(
            "http://example.com/2", "Entry 2", html_summary, "http://example.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    mock_smtp.reset_mock()
    main()

    # Email sent
    assert get_email_count(mock_smtp) == 1
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    email_str = sendmail_mock.call_args[0][2]
    email_body = get_email_body(email_str)

    # HTML preserved and content-type is HTML
    assert "text/html" in email_str.lower()
    assert "<strong>" in email_body or "bold" in email_body


def test_feed_title_in_email_from_header(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test 24: Feed title appears in email From header."""
    from meed import main

    feed_title = "My Test Feed"
    initial_entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(initial_entries, feed_title=feed_title))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()

    # Add new entry
    new_entries = [
        *initial_entries,
        create_feed_entry(
            "http://example.com/2", "Entry 2", "Summary 2", "http://example.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
        ),
    ]
    feed_file.write_text(create_rss_feed(new_entries, feed_title=feed_title))

    mock_smtp.reset_mock()
    main()

    # Email sent
    assert get_email_count(mock_smtp) == 1
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    email_str = sendmail_mock.call_args[0][2]

    # Feed title in From header
    assert feed_title in email_str
    assert "From:" in email_str


def test_feed_entry_no_id_uses_title(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test that feed entry with no ID or link but with title uses title as ID."""
    from meed import main

    entries = [
        create_feed_entry(
            None,  # No ID
            "Entry Title",
            "Summary",
            None,  # No link
            "Mon, 01 Jan 2025 10:00:00 GMT",
        )
    ]
    feed_xml = create_rss_feed(entries)
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(feed_xml)

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # First run - creates state
    main()
    assert_no_emails_sent(mock_smtp)

    # Update feed with new entry
    new_entries = [
        *entries,
        create_feed_entry(
            None,
            "New Entry",
            "New Summary",
            None,
            "Mon, 01 Jan 2025 11:00:00 GMT",
        ),
    ]
    feed_xml = create_rss_feed(new_entries)
    feed_file.write_text(feed_xml)

    # Second run - should send email
    main()
    assert get_email_count(mock_smtp) == 1


def test_feed_entry_no_link(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test that feed entry with no link uses ID as link."""
    from meed import main

    entries = [
        create_feed_entry(
            "http://example.com/entry-1",
            "Entry Title",
            "Summary",
            None,  # No link
            "Mon, 01 Jan 2025 10:00:00 GMT",
        )
    ]
    feed_xml = create_rss_feed(entries)
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(feed_xml)

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # First run
    main()
    assert_no_emails_sent(mock_smtp)

    # Add new entry and verify link handling
    new_entries = [
        *entries,
        create_feed_entry(
            "http://example.com/entry-2",
            "New Entry",
            "New Summary",
            None,
            "Mon, 01 Jan 2025 11:00:00 GMT",
        ),
    ]
    feed_xml = create_rss_feed(new_entries)
    feed_file.write_text(feed_xml)

    main()
    assert get_email_count(mock_smtp) == 1


def test_feeds_file_does_not_exist(mock_smtp: MagicMock) -> None:
    """Test handling when feeds file does not exist."""
    from meed import main

    # Delete the feeds file
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    feeds_file.unlink()

    # Should not crash
    main()
    assert_no_emails_sent(mock_smtp)


def test_document_that_is_not_a_feed_gets_no_state(
    test_env: Path, mock_smtp: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    """An XML document that is not RSS or Atom, such as an error page, is a failed fetch and gets no state."""
    import pytest

    from meed import Feed, FeedFetchError, main

    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text('<?xml version="1.0"?><root></root>')
    feed_url = f"file://{feed_file}"

    with pytest.raises(FeedFetchError, match="is not an RSS or Atom feed"):
        Feed.from_url(feed_url)

    create_feeds_file([feed_url], Path(os.environ["MEED_FEEDS_FILE_PATH"]))
    main()

    assert_no_emails_sent(mock_smtp)
    assert query_db(Path(os.environ["MEED_STATE_DB_PATH"]), "SELECT COUNT(*) FROM feeds")[0][0] == 0
    assert f"Error fetching or parsing feed {feed_url}: {feed_url} is not an RSS or Atom feed" in caplog.messages


def test_feed_get_new_entries_with_no_last_id(test_env: Path) -> None:
    """Test that get_new_entries returns all entries when last_id is None."""
    from meed import Feed

    entries = [
        create_feed_entry(
            "http://example.com/entry-1",
            "Entry 1",
            "Summary 1",
            "http://example.com/1",
            "Mon, 01 Jan 2025 10:00:00 GMT",
        ),
        create_feed_entry(
            "http://example.com/entry-2",
            "Entry 2",
            "Summary 2",
            "http://example.com/2",
            "Mon, 01 Jan 2025 11:00:00 GMT",
        ),
    ]
    feed_xml = create_rss_feed(entries)
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(feed_xml)

    feed_url = f"file://{feed_file}"
    feed = Feed.from_url(feed_url)

    # When last_id is None, should return all entries
    new_entries = feed.get_new_entries(None)
    assert len(new_entries) == 2


def test_job_function_exception_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that job() function handles exceptions properly."""
    from meed import job

    # Mock check_feeds to raise an exception
    def mock_check_feeds() -> None:
        raise ValueError("Test exception")

    monkeypatch.setattr("meed.check_feeds", mock_check_feeds)

    # Should not crash, exception should be caught
    job()


def test_unreachable_new_feed_gets_no_state(mock_smtp: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    """A new feed that cannot be fetched gets no state, so its first successful fetch only records its entries."""
    from meed import main

    # Nothing listens on port 1, so the connection is refused.
    feed_url = "http://127.0.0.1:1/feed.xml"
    create_feeds_file([feed_url], Path(os.environ["MEED_FEEDS_FILE_PATH"]))

    main()

    assert_no_emails_sent(mock_smtp)
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    assert query_db(state_db, "SELECT COUNT(*) FROM feeds WHERE id = ?", (feed_url,))[0][0] == 0
    assert any(f"Error fetching or parsing feed {feed_url}" in record.message for record in caplog.records)


def test_main_sets_network_timeout() -> None:
    """main() bounds every network operation, so a stalled connection cannot keep a run going."""
    import socket

    from meed import NETWORK_TIMEOUT, main

    try:
        main()
        assert socket.getdefaulttimeout() == NETWORK_TIMEOUT
    finally:
        socket.setdefaulttimeout(None)


def test_logging_json_formatter_with_extra() -> None:
    """Test MeedJSONFormatter with extra attributes."""
    import logging

    from meed import MeedJSONFormatter

    formatter = MeedJSONFormatter()

    # Create a log record with extra attributes
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    record.taskName = "test_task"
    record.custom_field = "custom_value"

    # Format the record
    formatted = formatter.format(record)

    # Should contain the custom field
    assert "custom_field" in formatted
    assert "custom_value" in formatted
    assert "test_task" in formatted


def test_logging_json_formatter_with_exception() -> None:
    """Test MeedJSONFormatter with exception info."""
    import logging
    import sys

    from meed import MeedJSONFormatter

    formatter = MeedJSONFormatter()

    def raise_test_error() -> None:
        raise ValueError("Test exception")

    try:
        raise_test_error()
    except ValueError:
        exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )
        record.taskName = "test_task"

        # Format the record
        formatted = formatter.format(record)

        # Should contain stack trace
        assert "stack_trace" in formatted
        assert "ValueError" in formatted
        assert "Test exception" in formatted


def test_feed_entry_no_id_no_link_no_title_raises_error(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test that feed entry with no ID, link, or title raises InvalidFeedEntryError."""
    from meed import main

    # Create entry with no ID, no link, and no title
    entries = [
        create_feed_entry(
            None,  # No ID
            None,  # No title
            "Summary",
            None,  # No link
            "Mon, 01 Jan 2025 10:00:00 GMT",
        )
    ]
    feed_xml = create_rss_feed(entries)
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(feed_xml)

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Should not crash, invalid entry should be filtered out
    main()
    assert_no_emails_sent(mock_smtp)


def test_feedparser_uses_custom_user_agent() -> None:
    """Test that feedparser is configured with a custom User-Agent to avoid bot detection."""
    import tomllib
    from unittest.mock import patch

    from meed import Feed

    with patch("feedparser.parse") as mock_parse:
        mock_parse.return_value = {
            "version": "rss20",
            "feed": {"id": "http://example.com", "title": "Test Feed"},
            "entries": [],
        }

        Feed.from_url("http://example.com/feed")

        # Verify feedparser.parse was called with a custom agent parameter
        mock_parse.assert_called_once()
        call_kwargs = mock_parse.call_args[1]
        assert "agent" in call_kwargs
        # Should identify as meed, at the version in pyproject.toml
        project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())["project"]
        assert call_kwargs["agent"].startswith(f"meed/{project['version']} ")
        assert "github.com/Ch00k/meed" in call_kwargs["agent"]  # Should have project URL
        assert "feedparser" not in call_kwargs["agent"].lower()  # Should not contain default feedparser UA


def test_assert_email_sent_helper(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test the assert_email_sent helper function with body_contains parameter."""
    from meed import main

    entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Establish baseline
    main()

    # Add new entry
    new_entries = [
        *entries,
        create_feed_entry(
            "http://example.com/2",
            "Test Subject",
            "Unique Body Content",
            "http://example.com/2",
            "Mon, 01 Jan 2025 11:00:00 GMT",
        ),
    ]
    feed_file.write_text(create_rss_feed(new_entries))

    mock_smtp.reset_mock()
    main()

    # Verify email was sent - just check that the function works (covers lines 156-175)
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    sendmail_mock.assert_called_once()

    # Get the actual email content
    call_args = sendmail_mock.call_args[0]
    message_str = call_args[2]
    email_body = get_email_body(message_str)

    # Verify content
    assert "Test Subject" in message_str
    assert "Unique Body Content" in email_body


def test_assert_feed_state_helper(test_env: Path) -> None:
    """Test the assert_feed_state helper function."""
    from meed import main
    from tests.test_utils import assert_feed_state

    entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        )
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(entries))

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Create state
    main()

    # Test the helper function
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    assert_feed_state(state_db, feed_url, "http://example.com/1")


def test_get_email_body_empty() -> None:
    """Test get_email_body with an email that has no payload."""
    from tests.test_utils import get_email_body

    # Email with no payload
    email_str = "Subject: Test\nFrom: test@test.com\n\n"
    body = get_email_body(email_str)
    assert body == ""


def test_feed_with_mix_of_valid_and_invalid_entries(test_env: Path, mock_smtp: MagicMock) -> None:
    """Test feed processing with a mix of valid and invalid entries."""
    from meed import main

    # Manually construct RSS with invalid entry (no id, title, link, or date)
    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0">',
        "<channel>",
        "<title>Test Feed</title>",
        "<link>http://example.com/feed</link>",
        "<description>Test feed description</description>",
        "<item>",
        "<guid>http://example.com/1</guid>",
        "<title>Valid Entry 1</title>",
        "<link>http://example.com/1</link>",
        "<description>Summary 1</description>",
        "<pubDate>Mon, 01 Jan 2025 10:00:00 GMT</pubDate>",
        "</item>",
        "<item>",
        "<description>Summary 2</description>",
        "</item>",
        "<item>",
        "<guid>http://example.com/3</guid>",
        "<title>Valid Entry 3</title>",
        "<link>http://example.com/3</link>",
        "<description>Summary 3</description>",
        "<pubDate>Mon, 01 Jan 2025 12:00:00 GMT</pubDate>",
        "</item>",
        "</channel>",
        "</rss>",
    ]
    feed_xml = "\n".join(xml_parts)

    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(feed_xml)

    feed_url = f"file://{feed_file}"
    feeds_file = Path(os.environ["MEED_FEEDS_FILE_PATH"])
    create_feeds_file([feed_url], feeds_file)

    # Should not crash, should process valid entries only
    main()
    assert_no_emails_sent(mock_smtp)

    # Verify state was created with valid entry
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    rows = query_db(state_db, "SELECT last_entry_id FROM feeds WHERE id = ?", (feed_url,))
    assert len(rows) > 0


def _sent_subjects(mock_smtp: MagicMock) -> list[str]:
    """The Subject header of every email sent, in the order they were sent."""
    from email import message_from_string

    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    return [message_from_string(call.args[2])["Subject"] for call in sendmail_mock.call_args_list]


def test_failed_send_keeps_the_entries_already_sent(
    test_env: Path, mock_smtp: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    """When an email fails partway through a feed's new entries, the next run sends only the ones not sent yet.

    Three new entries arrive; the second email fails. The state must then point at the first entry, and the next
    run must send the second and third and nothing else.
    """
    from meed import main

    def entry(n: int) -> dict:
        return create_feed_entry(
            f"http://example.com/{n}",
            f"Entry {n}",
            f"Summary {n}",
            f"http://example.com/{n}",
            f"Mon, 01 Jan 2025 1{n}:00:00 GMT",
        )

    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed([entry(1)]))
    feed_url = f"file://{feed_file}"
    create_feeds_file([feed_url], Path(os.environ["MEED_FEEDS_FILE_PATH"]))
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])

    main()

    feed_file.write_text(create_rss_feed([entry(1), entry(2), entry(3), entry(4)]))
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail
    sendmail_mock.side_effect = [None, Exception("SMTP failed")]

    main()

    assert _sent_subjects(mock_smtp) == ["Entry 2", "Entry 3"]
    assert "Error processing feed Test Feed: SMTP failed" in caplog.messages
    assert_feed_state(state_db, feed_url, "http://example.com/2")

    mock_smtp.reset_mock()
    sendmail_mock.side_effect = None

    main()

    assert _sent_subjects(mock_smtp) == ["Entry 3", "Entry 4"]
    assert_feed_state(state_db, feed_url, "http://example.com/4")


def test_line_breaks_in_titles_are_sent_on_one_line(test_env: Path, mock_smtp: MagicMock) -> None:
    """A line break in an entry's or a feed's title is sent as a space: an email header cannot hold one."""
    from email import message_from_string

    from meed import main

    first = create_feed_entry(
        "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
    )
    second = create_feed_entry(
        "http://example.com/2", "Two\nlines", "Summary 2", "http://example.com/2", "Mon, 01 Jan 2025 11:00:00 GMT"
    )
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed([first], feed_title="Feed\nName"))
    feed_url = f"file://{feed_file}"
    create_feeds_file([feed_url], Path(os.environ["MEED_FEEDS_FILE_PATH"]))

    main()
    feed_file.write_text(create_rss_feed([first, second], feed_title="Feed\nName"))
    main()

    assert get_email_count(mock_smtp) == 1
    message = message_from_string(mock_smtp.return_value.__enter__.return_value.sendmail.call_args.args[2])
    assert message["Subject"] == "Two lines"
    assert message["From"] == "Feed Name <from@test.com>"
    assert_feed_state(Path(os.environ["MEED_STATE_DB_PATH"]), feed_url, "http://example.com/2")


def test_entries_of_a_feed_first_seen_empty_are_sent_oldest_first(test_env: Path, mock_smtp: MagicMock) -> None:
    """A feed with no entries when first seen gets state with no last entry; everything it later has is new.

    Those entries are sent oldest first, like any other new entries, whatever order the feed lists them in.
    """
    from meed import main

    entries = [
        create_feed_entry(
            f"http://example.com/{n}",
            f"Entry {n}",
            f"Summary {n}",
            f"http://example.com/{n}",
            f"Mon, 01 Jan 2025 1{n}:00:00 GMT",
        )
        for n in (3, 1, 2)
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed([]))
    feed_url = f"file://{feed_file}"
    create_feeds_file([feed_url], Path(os.environ["MEED_FEEDS_FILE_PATH"]))

    main()
    assert_no_emails_sent(mock_smtp)

    feed_file.write_text(create_rss_feed(entries))
    main()

    assert _sent_subjects(mock_smtp) == ["Entry 1", "Entry 2", "Entry 3"]
    assert_feed_state(Path(os.environ["MEED_STATE_DB_PATH"]), feed_url, "http://example.com/3")


def test_entry_with_unreadable_date_is_skipped(test_env: Path, caplog: pytest.LogCaptureFixture) -> None:
    """An entry whose date cannot be read is skipped with a warning, and the rest of the feed is processed."""
    from meed import main

    entries = [
        create_feed_entry(
            "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
        ),
        create_feed_entry("http://example.com/2", "Entry 2", "Summary 2", "http://example.com/2", "not a date"),
    ]
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed(entries))
    feed_url = f"file://{feed_file}"
    create_feeds_file([feed_url], Path(os.environ["MEED_FEEDS_FILE_PATH"]))

    main()

    assert any("http://example.com/2 has no published date" in record.message for record in caplog.records)
    assert_feed_state(Path(os.environ["MEED_STATE_DB_PATH"]), feed_url, "http://example.com/1")


def test_log_timestamp_is_utc(monkeypatch: pytest.MonkeyPatch) -> None:
    """The JSON log's timestamp is in UTC, which its Z says, whatever the machine's time zone."""
    import json
    import logging
    import time

    from meed import MeedJSONFormatter

    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "Test message", (), None)
    record.created = 0

    monkeypatch.setenv("TZ", "Asia/Tokyo")
    time.tzset()
    try:
        formatted = json.loads(MeedJSONFormatter().format(record))
    finally:
        monkeypatch.undo()
        time.tzset()

    assert formatted["timestamp"] == "1970-01-01T00:00:00.000000Z"


def test_read_feeds_file_skips_comments_and_blank_lines(tmp_path: Path) -> None:
    """Comments, indented ones included, and blank lines are not feeds."""
    from meed import read_feeds_file

    feeds_file = tmp_path / "feeds.txt"
    feeds_file.write_text("# blogs\nhttps://a.example/feed\n\n  # indented\n  https://b.example/feed  \n")

    assert read_feeds_file(feeds_file) == ["https://a.example/feed", "https://b.example/feed"]


def test_entries_with_the_same_date_are_sent_once(
    test_env: Path, mock_smtp: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    """New entries sharing a date are each sent exactly once, also when a send fails between them.

    The feed lists B before A, both dated 11:00. They are sent A then B. With the second send failing, the next run
    sends B and nothing else; once both are sent, a further run sends nothing.
    """
    from meed import main

    first = create_feed_entry(
        "http://example.com/1", "Entry 1", "Summary 1", "http://example.com/1", "Mon, 01 Jan 2025 10:00:00 GMT"
    )
    a, b = (
        create_feed_entry(
            f"http://example.com/{name}",
            f"Entry {name}",
            "Summary",
            f"http://example.com/{name}",
            "Mon, 01 Jan 2025 11:00:00 GMT",
        )
        for name in ("A", "B")
    )
    feed_file = test_env / "data" / "feed.xml"
    feed_file.write_text(create_rss_feed([first]))
    feed_url = f"file://{feed_file}"
    create_feeds_file([feed_url], Path(os.environ["MEED_FEEDS_FILE_PATH"]))
    state_db = Path(os.environ["MEED_STATE_DB_PATH"])
    sendmail_mock = mock_smtp.return_value.__enter__.return_value.sendmail

    main()

    feed_file.write_text(create_rss_feed([b, a, first]))
    sendmail_mock.side_effect = [None, Exception("SMTP failed")]
    main()

    assert _sent_subjects(mock_smtp) == ["Entry A", "Entry B"]
    assert "Error processing feed Test Feed: SMTP failed" in caplog.messages
    assert_feed_state(state_db, feed_url, "http://example.com/A")

    mock_smtp.reset_mock()
    sendmail_mock.side_effect = None
    main()

    assert _sent_subjects(mock_smtp) == ["Entry B"]
    assert_feed_state(state_db, feed_url, "http://example.com/B")

    mock_smtp.reset_mock()
    main()

    assert_no_emails_sent(mock_smtp)


def test_new_feed_answering_with_an_http_error_gets_no_state(
    serve_feed: Callable[..., str], mock_smtp: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    """A new feed whose server answers with an error gets no state, even when the error response is a feed."""
    from meed import main

    url = serve_feed(503, create_rss_feed([]))
    create_feeds_file([url], Path(os.environ["MEED_FEEDS_FILE_PATH"]))

    main()

    assert_no_emails_sent(mock_smtp)
    assert query_db(Path(os.environ["MEED_STATE_DB_PATH"]), "SELECT COUNT(*) FROM feeds")[0][0] == 0
    assert f"Error fetching or parsing feed {url}: HTTP 503 from {url}" in caplog.messages


def test_redirect_to_an_error_page_gets_no_state(
    serve_feed: Callable[..., str], mock_smtp: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    """A new feed whose URL redirects to an error page gets no state, although feedparser records the redirect's 301."""
    from meed import main

    target = serve_feed(503, "<!doctype html><html><body>Service Unavailable</body></html>")
    redirecting = serve_feed(301, "", {"Location": target})
    create_feeds_file([redirecting], Path(os.environ["MEED_FEEDS_FILE_PATH"]))

    main()

    assert_no_emails_sent(mock_smtp)
    assert query_db(Path(os.environ["MEED_STATE_DB_PATH"]), "SELECT COUNT(*) FROM feeds")[0][0] == 0
    assert any(f"{redirecting} is not an RSS or Atom feed" in message for message in caplog.messages)
