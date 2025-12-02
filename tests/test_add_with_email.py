from pathlib import Path

from _pytest.monkeypatch import MonkeyPatch

from meed import add_feed_to_file, is_valid_feed, parse_email_body


def test_parse_email_body_with_url_only() -> None:
    """Test parsing email with only a URL."""
    body = "https://example.com/feed.xml"
    url, category = parse_email_body(body)
    assert url == "https://example.com/feed.xml"
    assert category is None


def test_parse_email_body_with_url_and_category() -> None:
    """Test parsing email with URL and category."""
    body = "https://example.com/feed.xml\nBlogs"
    url, category = parse_email_body(body)
    assert url == "https://example.com/feed.xml"
    assert category == "Blogs"


def test_parse_email_body_with_whitespace() -> None:
    """Test parsing email with extra whitespace."""
    body = "\n  https://example.com/feed.xml  \n  \n  Tech News  \n"
    url, category = parse_email_body(body)
    assert url == "https://example.com/feed.xml"
    assert category == "Tech News"


def test_parse_email_body_empty() -> None:
    """Test parsing empty email body."""
    body = ""
    url, category = parse_email_body(body)
    assert url is None
    assert category is None


def test_parse_email_body_whitespace_only() -> None:
    """Test parsing email with only whitespace."""
    body = "   \n  \n  "
    url, category = parse_email_body(body)
    assert url is None
    assert category is None


def test_parse_email_body_multiline_category() -> None:
    """Test parsing email where only first two lines are used."""
    body = "https://example.com/feed.xml\nBlogs\nExtra line\nAnother line"
    url, category = parse_email_body(body)
    assert url == "https://example.com/feed.xml"
    assert category == "Blogs"


def test_add_feed_to_file_with_category(tmp_path: Path) -> None:
    """Test adding feed with category to file."""
    feeds_file = tmp_path / "feeds.txt"
    feeds_file.write_text("# Existing\nhttps://existing.com/feed\n")

    add_feed_to_file(feeds_file, "https://new.com/feed", "News")

    content = feeds_file.read_text()
    assert "# News" in content
    assert "https://new.com/feed" in content
    assert content.endswith("https://new.com/feed\n")


def test_add_feed_to_file_without_category(tmp_path: Path) -> None:
    """Test adding feed without category adds to uncategorized."""
    feeds_file = tmp_path / "feeds.txt"
    feeds_file.write_text("# Existing\nhttps://existing.com/feed\n")

    add_feed_to_file(feeds_file, "https://new.com/feed")

    content = feeds_file.read_text()
    assert "# uncategorized" in content
    assert "https://new.com/feed" in content


def test_add_feed_to_file_without_category_reuses_uncategorized(tmp_path: Path) -> None:
    """Test adding multiple feeds without category reuses uncategorized section."""
    feeds_file = tmp_path / "feeds.txt"
    feeds_file.write_text("# uncategorized\nhttps://uncategorized1.com/feed\n")

    add_feed_to_file(feeds_file, "https://uncategorized2.com/feed")

    content = feeds_file.read_text()
    # Should only have one "# uncategorized" comment
    assert content.count("# uncategorized") == 1
    assert "https://uncategorized1.com/feed" in content
    assert "https://uncategorized2.com/feed" in content


def test_add_feed_to_file_creates_file(tmp_path: Path) -> None:
    """Test adding feed creates file if it doesn't exist."""
    feeds_file = tmp_path / "feeds.txt"

    add_feed_to_file(feeds_file, "https://new.com/feed", "Blogs")

    assert feeds_file.exists()
    content = feeds_file.read_text()
    assert "# Blogs" in content
    assert "https://new.com/feed" in content


def test_add_feed_to_file_reuses_existing_category(tmp_path: Path) -> None:
    """Test adding multiple feeds to same category doesn't duplicate category comment."""
    feeds_file = tmp_path / "feeds.txt"
    feeds_file.write_text("# Blogs\nhttps://blog1.com/feed\n\n# News\nhttps://news1.com/feed\n")

    add_feed_to_file(feeds_file, "https://blog2.com/feed", "Blogs")

    content = feeds_file.read_text()
    # Should only have one "# Blogs" comment
    assert content.count("# Blogs") == 1
    # Both blog feeds should be present
    assert "https://blog1.com/feed" in content
    assert "https://blog2.com/feed" in content
    # New feed should be added after the existing blog feed, before News section
    lines = content.split("\n")
    blog1_index = lines.index("https://blog1.com/feed")
    blog2_index = lines.index("https://blog2.com/feed")
    news_index = lines.index("# News")
    assert blog1_index < blog2_index < news_index


def test_add_feed_to_file_category_at_end(tmp_path: Path) -> None:
    """Test adding feed to category that's at the end of file."""
    feeds_file = tmp_path / "feeds.txt"
    feeds_file.write_text("# News\nhttps://news1.com/feed\n\n# Blogs\nhttps://blog1.com/feed\n")

    add_feed_to_file(feeds_file, "https://blog2.com/feed", "Blogs")

    content = feeds_file.read_text()
    assert content.count("# Blogs") == 1
    assert "https://blog2.com/feed" in content
    # New feed should be after existing blog feed
    lines = [line for line in content.split("\n") if line.strip()]
    assert "https://blog1.com/feed" in lines
    assert "https://blog2.com/feed" in lines


def test_is_valid_feed_with_mock(monkeypatch: MonkeyPatch) -> None:
    """Test feed validation with mocked feedparser."""
    from unittest.mock import MagicMock

    mock_parse = MagicMock()

    # Test valid feed
    mock_parse.return_value = MagicMock(entries=[{"id": "1"}])
    monkeypatch.setattr("meed.feedparser.parse", mock_parse)

    result = is_valid_feed("https://example.com/feed")
    assert result is True

    # Test exception
    mock_parse.side_effect = Exception("Network error")
    result = is_valid_feed("https://example.com/feed")
    assert result is False


def test_process_email_with_valid_feed(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    """Test process_email with a valid feed URL."""
    from unittest.mock import MagicMock

    from meed import process_email

    feeds_file = tmp_path / "feeds.txt"
    monkeypatch.setenv("MEED_FEEDS_FILE_PATH", str(feeds_file))

    # Create a mock email message
    mock_msg = MagicMock()
    mock_msg.uid = "12345"
    mock_msg.text = "https://example.com/feed\nBlogs"
    mock_msg.html = None

    # Mock is_valid_feed to return True
    monkeypatch.setattr("meed.is_valid_feed", lambda _: True)

    # Process the email
    process_email(mock_msg)

    # Verify feed was added to file
    content = feeds_file.read_text()
    assert "https://example.com/feed" in content
    assert "# Blogs" in content


def test_process_email_with_invalid_feed(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    """Test process_email with an invalid feed URL."""
    from unittest.mock import MagicMock

    from meed import process_email

    feeds_file = tmp_path / "feeds.txt"
    feeds_file.write_text("")
    monkeypatch.setenv("MEED_FEEDS_FILE_PATH", str(feeds_file))

    # Create a mock email message
    mock_msg = MagicMock()
    mock_msg.uid = "12345"
    mock_msg.text = "https://invalid.com/notafeed"
    mock_msg.html = None

    # Mock is_valid_feed to return False
    monkeypatch.setattr("meed.is_valid_feed", lambda _: False)

    # Process the email
    process_email(mock_msg)

    # Verify feed was NOT added to file
    content = feeds_file.read_text()
    assert "https://invalid.com/notafeed" not in content


def test_process_email_with_no_body() -> None:
    """Test process_email with email that has no body."""
    from unittest.mock import MagicMock

    from meed import process_email

    # Create a mock email message with no body
    mock_msg = MagicMock()
    mock_msg.uid = "12345"
    mock_msg.text = None
    mock_msg.html = None

    # Should not crash
    process_email(mock_msg)


def test_process_email_with_no_uid(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    """Test process_email with email that has no UID."""
    from unittest.mock import MagicMock

    from meed import process_email

    feeds_file = tmp_path / "feeds.txt"
    feeds_file.write_text("")
    monkeypatch.setenv("MEED_FEEDS_FILE_PATH", str(feeds_file))

    # Create a mock email message with no UID
    mock_msg = MagicMock()
    mock_msg.uid = None
    mock_msg.text = "https://example.com/feed"
    mock_msg.html = None

    # Mock is_valid_feed to return True
    monkeypatch.setattr("meed.is_valid_feed", lambda _: True)

    # Should not crash
    process_email(mock_msg)


def test_process_email_with_empty_url(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    """Test process_email with email containing empty lines."""
    from unittest.mock import MagicMock

    from meed import process_email

    feeds_file = tmp_path / "feeds.txt"
    feeds_file.write_text("")
    monkeypatch.setenv("MEED_FEEDS_FILE_PATH", str(feeds_file))

    # Create a mock email message with whitespace only
    mock_msg = MagicMock()
    mock_msg.uid = "12345"
    mock_msg.text = "   \n\n   "
    mock_msg.html = None

    # Should not crash, should return early
    process_email(mock_msg)

    # Verify nothing was added
    content = feeds_file.read_text()
    assert content == ""


def test_check_emails_not_configured(monkeypatch: MonkeyPatch) -> None:
    """Test check_emails when IMAP is not configured."""

    # Clear IMAP configuration
    monkeypatch.setenv("MEED_IMAP_HOST", "")
    monkeypatch.delenv("MEED_IMAP_HOST", raising=False)

    # Reload the module to pick up new env vars
    import importlib

    import meed

    importlib.reload(meed)

    # Should return early with warning
    meed.check_emails()


def test_check_emails_with_messages(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    """Test check_emails with unread messages in mailbox."""
    from unittest.mock import MagicMock, patch

    feeds_file = tmp_path / "feeds.txt"
    feeds_file.write_text("")
    monkeypatch.setenv("MEED_FEEDS_FILE_PATH", str(feeds_file))
    monkeypatch.setenv("MEED_IMAP_HOST", "imap.test.com")
    monkeypatch.setenv("MEED_IMAP_USER", "test@test.com")
    monkeypatch.setenv("MEED_IMAP_PASSWORD", "testpass")

    # Reload the module to pick up new env vars
    import importlib

    import meed

    importlib.reload(meed)

    # Create mock messages
    mock_msg1 = MagicMock()
    mock_msg1.uid = "123"
    mock_msg1.text = "https://example.com/feed1"
    mock_msg1.html = None

    mock_msg2 = MagicMock()
    mock_msg2.uid = "124"
    mock_msg2.text = "https://example.com/feed2"
    mock_msg2.html = None

    # Mock MailBox
    mock_mailbox = MagicMock()
    mock_mailbox.fetch.return_value = [mock_msg1, mock_msg2]

    with patch("meed.MailBox") as mock_mailbox_class, patch("meed.is_valid_feed", return_value=True):
        mock_mailbox_class.return_value.login.return_value.__enter__.return_value = mock_mailbox

        meed.check_emails()

        # Verify messages were marked as read
        mock_mailbox.flag.assert_called_once()
        call_args = mock_mailbox.flag.call_args[0]
        assert "123" in call_args[0]
        assert "124" in call_args[0]


def test_check_emails_no_unread(monkeypatch: MonkeyPatch) -> None:
    """Test check_emails with no unread messages."""
    from unittest.mock import MagicMock, patch

    monkeypatch.setenv("MEED_IMAP_HOST", "imap.test.com")
    monkeypatch.setenv("MEED_IMAP_USER", "test@test.com")
    monkeypatch.setenv("MEED_IMAP_PASSWORD", "testpass")

    # Reload the module to pick up new env vars
    import importlib

    import meed

    importlib.reload(meed)

    # Mock MailBox with no messages
    mock_mailbox = MagicMock()
    mock_mailbox.fetch.return_value = []

    with patch("meed.MailBox") as mock_mailbox_class:
        mock_mailbox_class.return_value.login.return_value.__enter__.return_value = mock_mailbox

        meed.check_emails()

        # Verify flag was not called
        mock_mailbox.flag.assert_not_called()


def test_job_handles_check_emails_exception(monkeypatch: MonkeyPatch) -> None:
    """Test that job() handles exceptions from check_emails."""
    from meed import job

    # Mock check_emails to raise an exception
    def mock_check_emails() -> None:
        raise ValueError("IMAP error")

    monkeypatch.setattr("meed.check_emails", mock_check_emails)

    # Mock check_feeds to not raise
    monkeypatch.setattr("meed.check_feeds", lambda: None)

    # Should not crash, exception should be caught
    job()
