from typing import TYPE_CHECKING

from meed import add_feed, is_valid_feed, parse_email_body, parse_feeds
from tests.test_utils import create_atom_feed, create_rss_feed, delete_bucket, get_object, put_object

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest
    from _pytest.monkeypatch import MonkeyPatch


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


def test_add_feed_with_category() -> None:
    """Test adding feed with category to file."""
    content = add_feed("# Existing\nhttps://existing.com/feed\n", "https://new.com/feed", "News")

    assert "# News" in content
    assert "https://new.com/feed" in content
    assert content.endswith("https://new.com/feed\n")


def test_add_feed_without_category() -> None:
    """Test adding feed without category adds to uncategorized."""
    content = add_feed("# Existing\nhttps://existing.com/feed\n", "https://new.com/feed")

    assert "# uncategorized" in content
    assert "https://new.com/feed" in content


def test_add_feed_without_category_reuses_uncategorized() -> None:
    """Test adding multiple feeds without category reuses uncategorized section."""
    content = add_feed("# uncategorized\nhttps://uncategorized1.com/feed\n", "https://uncategorized2.com/feed")

    # Should only have one "# uncategorized" comment
    assert content.count("# uncategorized") == 1
    assert "https://uncategorized1.com/feed" in content
    assert "https://uncategorized2.com/feed" in content


def test_add_feed_to_an_empty_list() -> None:
    """A feed added to an empty list starts its category."""
    assert add_feed("", "https://new.com/feed", "Blogs") == "\n\n# Blogs\nhttps://new.com/feed\n"


def test_add_feed_reuses_existing_category() -> None:
    """Test adding multiple feeds to same category doesn't duplicate category comment."""
    content = add_feed(
        "# Blogs\nhttps://blog1.com/feed\n\n# News\nhttps://news1.com/feed\n", "https://blog2.com/feed", "Blogs"
    )

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


def test_add_feed_keeps_the_category_together() -> None:
    """A URL added to a category goes right after its last URL, keeping the blank line between categories."""
    feeds = "# Blogs\nhttps://blog1.com/feed\n\n# News\nhttps://news1.com/feed"

    feeds = add_feed(feeds, "https://blog2.com/feed", "Blogs")
    feeds = add_feed(feeds, "https://news2.com/feed", "News")

    assert feeds == (
        "# Blogs\nhttps://blog1.com/feed\nhttps://blog2.com/feed\n\n# News\nhttps://news1.com/feed\nhttps://news2.com/feed\n"
    )


def test_add_feed_category_at_end() -> None:
    """Test adding feed to category that's at the end of file."""
    content = add_feed(
        "# News\nhttps://news1.com/feed\n\n# Blogs\nhttps://blog1.com/feed\n", "https://blog2.com/feed", "Blogs"
    )

    assert content.count("# Blogs") == 1
    assert "https://blog2.com/feed" in content
    # New feed should be after existing blog feed
    lines = [line for line in content.split("\n") if line.strip()]
    assert "https://blog1.com/feed" in lines
    assert "https://blog2.com/feed" in lines


def test_is_valid_feed_accepts_rss_and_atom(serve_feed: Callable[..., str]) -> None:
    """An RSS or Atom document served over HTTP is a feed."""
    assert is_valid_feed(serve_feed(200, create_rss_feed([]))) is True
    assert is_valid_feed(serve_feed(200, create_atom_feed([]))) is True


def test_is_valid_feed_rejects_a_web_page(serve_feed: Callable[..., str]) -> None:
    """An HTML page is not a feed, although feedparser parses it without an error."""
    page = "<!doctype html><html><head><title>Blog</title></head><body><p>Hello</p></body></html>"

    assert is_valid_feed(serve_feed(200, page)) is False


def test_is_valid_feed_rejects_an_http_error(serve_feed: Callable[..., str], caplog: pytest.LogCaptureFixture) -> None:
    """A feed document served with an error status is not a feed, and the error is logged."""
    url = serve_feed(404, create_rss_feed([]))

    assert is_valid_feed(url) is False
    assert f"Error validating feed {url}: HTTP 404 from {url}" in caplog.messages


def test_is_valid_feed_rejects_what_is_not_an_http_url(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A local file or a literal XML document is not a URL to poll, although feedparser reads both as feeds."""
    feed_file = tmp_path / "feed.xml"
    feed_file.write_text(create_rss_feed([]))
    inline = '<rss version="2.0"><channel><title>Inline</title></channel></rss>'

    assert is_valid_feed(f"file://{feed_file}") is False
    assert is_valid_feed(str(feed_file)) is False
    assert is_valid_feed(inline) is False
    assert f"file://{feed_file} is not an HTTP(S) URL" in caplog.messages


def test_is_valid_feed_rejects_a_malformed_url(caplog: pytest.LogCaptureFixture) -> None:
    """A URL that cannot even be parsed is not a feed, and the error is logged instead of raised."""
    url = "http://[::1/feed.xml"

    assert is_valid_feed(url) is False
    assert any(f"Error validating feed {url}" in message for message in caplog.messages)


def test_is_valid_feed_rejects_an_unreachable_url(caplog: pytest.LogCaptureFixture) -> None:
    """A URL that cannot be fetched is not a feed, and the failure is logged."""
    # Nothing listens on port 1, so the connection is refused.
    url = "http://127.0.0.1:1/feed.xml"

    assert is_valid_feed(url) is False
    assert any(f"Error validating feed {url}" in message for message in caplog.messages)


def test_process_email_with_valid_feed(monkeypatch: MonkeyPatch) -> None:
    """Test process_email with a valid feed URL, with no feed list in the bucket yet."""
    from unittest.mock import MagicMock

    from meed import process_email

    # Create a mock email message
    mock_msg = MagicMock()
    mock_msg.uid = "12345"
    mock_msg.text = "https://example.com/feed\nBlogs"
    mock_msg.html = None

    # Mock is_valid_feed to return True
    monkeypatch.setattr("meed.is_valid_feed", lambda _: True)

    # Process the email
    process_email(mock_msg)

    # Verify feed was added to the feed list
    assert get_object("feeds.txt") == "\n\n# Blogs\nhttps://example.com/feed\n"


def test_process_email_skips_a_feed_already_listed(monkeypatch: MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    """A feed already in the feed list is not added again, under any category, and is not fetched."""
    from unittest.mock import MagicMock

    from meed import process_email

    put_object("feeds.txt", "# Blogs\nhttps://example.com/feed\n")

    def fail_validation(url: str) -> bool:
        msg = f"{url} was fetched"
        raise AssertionError(msg)

    monkeypatch.setattr("meed.is_valid_feed", fail_validation)
    mock_msg = MagicMock(uid="12345", text="https://example.com/feed\nNews", html=None)
    caplog.set_level("INFO")

    process_email(mock_msg)

    assert get_object("feeds.txt") == "# Blogs\nhttps://example.com/feed\n"
    assert "Feed https://example.com/feed is already in the feed list" in caplog.messages


def test_process_email_with_invalid_feed(monkeypatch: MonkeyPatch) -> None:
    """Test process_email with an invalid feed URL."""
    from unittest.mock import MagicMock

    from meed import process_email

    put_object("feeds.txt", "")

    # Create a mock email message
    mock_msg = MagicMock()
    mock_msg.uid = "12345"
    mock_msg.text = "https://invalid.com/notafeed"
    mock_msg.html = None

    # Mock is_valid_feed to return False
    monkeypatch.setattr("meed.is_valid_feed", lambda _: False)

    # Process the email
    process_email(mock_msg)

    # Verify feed was NOT added to the feed list
    assert get_object("feeds.txt") == ""


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


def test_process_email_with_no_uid(monkeypatch: MonkeyPatch) -> None:
    """Test process_email with email that has no UID."""
    from unittest.mock import MagicMock

    from meed import process_email

    put_object("feeds.txt", "")

    # Create a mock email message with no UID
    mock_msg = MagicMock()
    mock_msg.uid = None
    mock_msg.text = "https://example.com/feed"
    mock_msg.html = None

    # Mock is_valid_feed to return True
    monkeypatch.setattr("meed.is_valid_feed", lambda _: True)

    # Should not crash
    process_email(mock_msg)


def test_process_email_with_empty_url() -> None:
    """Test process_email with email containing empty lines."""
    from unittest.mock import MagicMock

    from meed import process_email

    put_object("feeds.txt", "")

    # Create a mock email message with whitespace only
    mock_msg = MagicMock()
    mock_msg.uid = "12345"
    mock_msg.text = "   \n\n   "
    mock_msg.html = None

    # Should not crash, should return early
    process_email(mock_msg)

    # Verify nothing was added
    assert get_object("feeds.txt") == ""


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


def test_check_emails_with_messages(monkeypatch: MonkeyPatch) -> None:
    """Test check_emails with unread messages in mailbox."""
    from unittest.mock import MagicMock, call, patch

    from imap_tools import MailMessageFlags

    put_object("feeds.txt", "")
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

        # Both feeds were added, and each message was marked as read once handled
        mock_mailbox.fetch.assert_called_once_with(criteria="UNSEEN", mark_seen=False)
        assert parse_feeds(get_object("feeds.txt") or "") == ["https://example.com/feed1", "https://example.com/feed2"]
        assert mock_mailbox.flag.call_args_list == [
            call("123", MailMessageFlags.SEEN, value=True),
            call("124", MailMessageFlags.SEEN, value=True),
        ]


def test_check_emails_leaves_messages_it_could_not_handle_unread(monkeypatch: MonkeyPatch) -> None:
    """When the bucket cannot be reached, no message is marked as read, so the next run handles them all."""
    from unittest.mock import MagicMock, patch

    import pytest
    from botocore.exceptions import ClientError

    monkeypatch.setenv("MEED_IMAP_HOST", "imap.test.com")
    monkeypatch.setenv("MEED_IMAP_USER", "test@test.com")
    monkeypatch.setenv("MEED_IMAP_PASSWORD", "testpass")

    import meed

    delete_bucket()
    mock_mailbox = MagicMock()
    mock_mailbox.fetch.return_value = [
        MagicMock(uid="123", text="https://example.com/feed1", html=None),
        MagicMock(uid="124", text="https://example.com/feed2", html=None),
    ]

    with patch("meed.MailBox") as mock_mailbox_class, patch("meed.is_valid_feed", return_value=True):
        mock_mailbox_class.return_value.login.return_value.__enter__.return_value = mock_mailbox

        with pytest.raises(ClientError, match="NoSuchBucket"):
            meed.check_emails()

    mock_mailbox.flag.assert_not_called()


def test_process_email_finds_the_category_of_a_list_with_crlf_line_endings(monkeypatch: MonkeyPatch) -> None:
    """A feed list with Windows line endings gets the feed under its existing heading, and Unix line endings."""
    from unittest.mock import MagicMock

    from meed import process_email

    put_object("feeds.txt", "# Blogs\r\nhttps://blog1.com/feed\r\n\r\n# News\r\nhttps://news1.com/feed\r\n")
    monkeypatch.setattr("meed.is_valid_feed", lambda _: True)

    process_email(MagicMock(uid="123", text="https://blog2.com/feed\nBlogs", html=None))

    assert get_object("feeds.txt") == (
        "# Blogs\nhttps://blog1.com/feed\nhttps://blog2.com/feed\n\n# News\nhttps://news1.com/feed\n"
    )


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

        # No feed was added
        assert get_object("feeds.txt") is None


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
