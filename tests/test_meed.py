# ABOUTME: Comprehensive test suite for meed RSS/Atom feed email notification system.
# ABOUTME: Tests cover feed processing, entry validation, email sending, and error handling.

import os
from pathlib import Path
from unittest.mock import MagicMock

from tests.test_utils import (
    assert_no_emails_sent,
    create_feed_entry,
    create_feeds_file,
    create_rss_feed,
    query_db,
)


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
    main(run_once=True)

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
