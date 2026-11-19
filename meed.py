import logging
import smtplib
import socket
import sqlite3
import tomllib
import urllib.error
from contextlib import contextmanager
from datetime import UTC, datetime
from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import environs
import feedparser
import sentry_sdk
from imap_tools import MailBox
from json_log_formatter import BUILTIN_ATTRS, JSONFormatter
from pydantic import BaseModel, Field, model_validator

if TYPE_CHECKING:
    from collections.abc import Generator

    from imap_tools.message import MailMessage

BUILTIN_ATTRS.add("taskName")

logger = logging.getLogger(__name__)


class MeedJSONFormatter(JSONFormatter):
    def extra_from_record(self, record: logging.LogRecord) -> dict:
        return {
            attr_name: record.__dict__[attr_name] for attr_name in record.__dict__ if attr_name not in BUILTIN_ATTRS
        }

    def json_record(self, message: str, extra: dict, record: logging.LogRecord) -> dict:
        new_extra: dict[str, Any] = {}

        timestamp = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="microseconds")
        new_extra["timestamp"] = timestamp.replace("+00:00", "Z")
        new_extra["level"] = record.levelname
        new_extra["logger"] = record.name
        new_extra["module"] = record.module
        new_extra["function"] = record.funcName
        new_extra["task"] = record.taskName
        new_extra["stack_trace"] = self.formatException(record.exc_info) if record.exc_info else None
        new_extra["message"] = message

        new_extra["extra"] = str(extra) if extra else None
        return new_extra


class InvalidFeedEntryError(Exception):
    """Raised when a feed entry cannot be parsed due to missing required fields."""


class FeedFetchError(Exception):
    """Raised when a feed's server answers with an HTTP error, or with something that is not a feed."""


env = environs.Env()

FEEDS_FILE_PATH = env.path("MEED_FEEDS_FILE_PATH", Path("feeds.txt"))
STATE_DB_PATH = env.path("MEED_STATE_DB_PATH", Path("state.db"))

SMTP_HOST = env.str("MEED_SMTP_HOST", "127.0.0.1")
SMTP_PORT = env.int("MEED_SMTP_PORT", 465)
SMTP_USER = env.str("MEED_SMTP_USER", "user")
SMTP_PASSWORD = env.str("MEED_SMTP_PASSWORD", "password")

EMAIL_FROM = env.str("MEED_EMAIL_FROM", "meed@example.com")
EMAIL_TO = env.str("MEED_EMAIL_TO", "my@e.mail")

IMAP_HOST = env.str("MEED_IMAP_HOST", None)
IMAP_PORT = env.int("MEED_IMAP_PORT", 993)
IMAP_USER = env.str("MEED_IMAP_USER", None)
IMAP_PASSWORD = env.str("MEED_IMAP_PASSWORD", None)
IMAP_MAILBOX = env.str("MEED_IMAP_MAILBOX", "INBOX.meed")

SENTRY_DSN = env.str("MEED_SENTRY_DSN", None)

# Seconds a feed fetch, SMTP or IMAP connection may stall. Without a limit, one stalled connection keeps the run,
# and the Machine it runs on, going forever.
NETWORK_TIMEOUT = 60

# A feed's row says meed knows it. last_entry_id is set only on a row from before meed recorded every entry it has seen:
# the newest entry it had sent. The first run that finds one turns it into seen entries and clears it.
SQL_CREATE_STATE_TABLE = "CREATE TABLE IF NOT EXISTS feeds (id TEXT, last_checked_at DATETIME, last_entry_id TEXT)"
# Every entry of a feed meed has seen: emailed, or already in the feed when meed first checked it.
SQL_CREATE_SEEN_TABLE = (
    "CREATE TABLE IF NOT EXISTS seen_entries (feed_id TEXT NOT NULL, entry_id TEXT NOT NULL, "
    "PRIMARY KEY (feed_id, entry_id))"
)
SQL_GET_STATE = "SELECT last_entry_id FROM feeds WHERE id = ?"
SQL_CREATE_STATE = "INSERT INTO feeds (id, last_checked_at, last_entry_id) VALUES (?, datetime('now'), NULL)"
SQL_CLEAR_LAST_ENTRY = "UPDATE feeds SET last_entry_id = NULL WHERE id = ?"
SQL_UPDATE_LAST_CHECKED = "UPDATE feeds SET last_checked_at = datetime('now') WHERE id = ?"
SQL_GET_SEEN = "SELECT entry_id FROM seen_entries WHERE feed_id = ?"
SQL_ADD_SEEN = "INSERT OR IGNORE INTO seen_entries (feed_id, entry_id) VALUES (?, ?)"


# meed is not installed as a package, so there is no package metadata to read its version from.
VERSION = tomllib.loads(Path(__file__).with_name("pyproject.toml").read_text())["project"]["version"]

# Custom User-Agent to identify meed and avoid overly aggressive bot detection
USER_AGENT = f"meed/{VERSION} (+https://github.com/Ch00k/meed)"


@contextmanager
def get_db_cursor() -> Generator[sqlite3.Cursor]:
    conn = sqlite3.connect(STATE_DB_PATH)
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    finally:
        conn.close()


class FeedEntry(BaseModel):
    id: str
    title: str
    summary: str
    link: str
    published: datetime

    @model_validator(mode="before")
    @classmethod
    def ensure_fields(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Ensure id field exists
        if not value.get("id"):
            logger.warning("FeedEntry has no ID, attempting to use link or title as ID")
            if value.get("link"):
                logger.warning("Using link as ID")
                value["id"] = value["link"]
            elif value.get("title"):
                logger.warning("Using title as ID")
                value["id"] = value["title"]
            else:
                raise InvalidFeedEntryError("FeedEntry must have either ID, link, or title")

        # Ensure title field exists
        if not value.get("title"):
            logger.warning(f"FeedEntry {value['id']} has no title, using ID as title")
            value["title"] = value["id"]

        # Ensure link field exists
        if not value.get("link"):
            logger.warning(f"FeedEntry {value['id']} has no link, using ID as link")
            value["link"] = value["id"]

        # Ensure summary field exists
        if not value.get("summary"):
            logger.warning(f"FeedEntry {value['id']} has no summary, using ID as summary")
            value["summary"] = value["id"]

        # Determine published date. feedparser parses each date it can read into a UTC time.struct_time.
        published_date = value.get("published_parsed") or value.get("updated_parsed") or value.get("created_parsed")
        if not published_date:
            logger.warning(f"FeedEntry {value['id']} has no published date, skipping entry")
            raise InvalidFeedEntryError("FeedEntry must have a published, updated, or created date")

        value["published"] = datetime(*published_date[:6], tzinfo=UTC)

        return value

    def send_notification(self, feed_title: str) -> None:
        # A header cannot hold a line break, and feeds do put them in titles.
        msg = MIMEText(f"{self.link}<br><br>{self.summary}", "html", "utf-8")
        msg["From"] = formataddr((" ".join(feed_title.split()), EMAIL_FROM))
        msg["To"] = EMAIL_TO
        msg["Subject"] = " ".join(self.title.split())

        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())


class FeedMetadata(BaseModel):
    id: str
    title: str


class Feed(BaseModel):
    metadata: FeedMetadata = Field(alias="feed")
    entries: list[FeedEntry] = []

    @model_validator(mode="before")
    @classmethod
    def filter_invalid_entries(cls, value: dict[str, Any]) -> dict[str, Any]:
        if "entries" in value and isinstance(value["entries"], list):
            valid_entries = []
            for entry_data in value["entries"]:
                try:
                    # Create and validate FeedEntry instance
                    valid_entry = FeedEntry(**entry_data)
                    valid_entries.append(valid_entry)
                except InvalidFeedEntryError as e:
                    logger.warning(f"Skipping invalid entry: {e}")
                    continue
            value["entries"] = valid_entries
        return value

    @model_validator(mode="after")
    def sort_entries(self) -> Feed:
        if self.entries:
            # Sort entries by published date, newest first
            self.entries.sort(key=lambda e: e.published, reverse=True)
        return self

    @classmethod
    def from_url(cls, url: str) -> Feed:
        parsed_feed = fetch_feed(url)

        logger.info(f"Replacing feed ID with URL for feed {url}")
        parsed_feed["feed"]["id"] = url  # pyright: ignore[reportCallIssue,reportArgumentType]

        if not parsed_feed["feed"].get("title"):  # pyright: ignore[reportAttributeAccessIssue]
            logger.warning(f"Feed {url} has no title, using URL as title")
            parsed_feed["feed"]["title"] = url  # pyright: ignore[reportCallIssue,reportArgumentType]

        return cls(**parsed_feed)  # pyright: ignore[reportArgumentType]

    def get_new_entries(self, seen: set[str]) -> list[FeedEntry]:
        """The entries not seen yet, oldest first.

        Entries with the same date are sent in the reverse of the feed's order, which lists newer entries first.
        """
        return [entry for entry in reversed(self.entries) if entry.id not in seen]

    def process(self) -> None:
        if not self.is_known():
            logger.info(f"Feed {self.metadata.title} is new, creating state")
            self.create_state()
            return

        logger.info(f"Feed {self.metadata.title} is known, checking for new entries")

        last_entry_id = self.get_last_entry_id()
        if last_entry_id is not None:
            self.convert_last_entry_id(last_entry_id)

        new_entries = self.get_new_entries(self.get_seen_entry_ids())

        if new_entries:
            logger.info(f"Found {len(new_entries)} new entries")
        else:
            logger.info("No new entries found")

        # Each entry is recorded as seen as soon as its email is sent, so a run that fails partway resends nothing.
        for entry in new_entries:
            logger.info(f"Sending notification for entry {entry.title} ({entry.link})")
            entry.send_notification(self.metadata.title)
            self.add_seen_entries([entry.id])

    def get_state(self) -> tuple[str | None] | None:
        """The feed's stored row, holding its last entry ID, or None for a feed with no state yet."""
        with get_db_cursor() as cursor:
            logger.debug("Executing SQL: %s with params (%s)", SQL_GET_STATE, self.metadata.id)
            cursor.execute(SQL_GET_STATE, (self.metadata.id,))
            row = cursor.fetchone()

        logger.debug("Fetched state from DB: %s", row)
        return row

    def is_known(self) -> bool:
        return self.get_state() is not None

    def get_last_entry_id(self) -> str | None:
        row = self.get_state()
        return row[0] if row else None

    def get_seen_entry_ids(self) -> set[str]:
        with get_db_cursor() as cursor:
            cursor.execute(SQL_GET_SEEN, (self.metadata.id,))
            return {row[0] for row in cursor.fetchall()}

    def create_state(self) -> None:
        """Record the feed, with every entry it has now as seen: only entries published from here on are new."""
        with get_db_cursor() as cursor:
            logger.debug("Executing SQL: %s with params (%s)", SQL_CREATE_STATE, self.metadata.id)
            cursor.execute(SQL_CREATE_STATE, (self.metadata.id,))
            cursor.executemany(SQL_ADD_SEEN, [(self.metadata.id, entry.id) for entry in self.entries])

    def add_seen_entries(self, entry_ids: list[str]) -> None:
        with get_db_cursor() as cursor:
            logger.debug("Recording entries %s of feed %s as seen", entry_ids, self.metadata.id)
            cursor.executemany(SQL_ADD_SEEN, [(self.metadata.id, entry_id) for entry_id in entry_ids])
            cursor.execute(SQL_UPDATE_LAST_CHECKED, (self.metadata.id,))

    def convert_last_entry_id(self, last_entry_id: str) -> None:
        """Turn the newest entry sent, all a feed's state held before seen entries, into seen entries.

        That entry and every entry the feed lists after it count as seen. When it has left the feed, which entries
        are new cannot be told, so all of them count as seen and none is sent.
        """
        entry_ids = [entry.id for entry in self.entries]
        if last_entry_id in entry_ids:
            seen = entry_ids[entry_ids.index(last_entry_id) :]
        else:
            logger.warning(f"Last sent entry {last_entry_id} is no longer in feed {self.metadata.title}")
            seen = entry_ids

        logger.info(f"Recording {len(seen)} entries of feed {self.metadata.title} as seen, up to {last_entry_id}")
        with get_db_cursor() as cursor:
            cursor.executemany(SQL_ADD_SEEN, [(self.metadata.id, entry_id) for entry_id in seen])
            cursor.execute(SQL_CLEAR_LAST_ENTRY, (self.metadata.id,))


def read_feeds_file(file_path: Path) -> list[str]:
    if not file_path.exists():
        logger.warning(f"Feeds file {file_path} does not exist.")
        return []

    with Path.open(file_path) as f:
        lines = [line.strip() for line in f]

    return [line for line in lines if line and not line.startswith("#")]


def fetch_feed(url: str) -> feedparser.FeedParserDict:
    """Fetch and parse an RSS or Atom feed, raising when the fetch fails or what it fetched is not a feed.

    feedparser itself reports a failed fetch, or an error page, as an empty feed. Taken as one, a new feed would get
    state with no last entry, and its first successful fetch would email the whole backlog.
    """
    parsed_feed = feedparser.parse(url, agent=USER_AGENT)

    if isinstance(parsed_feed.get("bozo_exception"), urllib.error.URLError):
        raise parsed_feed["bozo_exception"]

    # feedparser parses the body of an error response too.
    status = parsed_feed.get("status", 200)
    if status >= 400:
        msg = f"HTTP {status} from {url}"
        raise FeedFetchError(msg)

    # feedparser names the format of a feed it recognises, such as rss20 or atom10. After a redirect, `status` holds
    # the redirect's code, so this is also what rejects an error page at the end of one.
    if not parsed_feed.get("version", "").startswith(("rss", "atom")):
        msg = f"{url} is not an RSS or Atom feed"
        raise FeedFetchError(msg)

    return parsed_feed


def parse_email_body(body: str) -> tuple[str | None, str | None]:
    """Parse email body to extract URL and optional category.

    Expected format:
    Line 1: URL
    Line 2 (optional): Category

    Returns tuple of (url, category) or (None, None) if parsing fails.
    """
    lines = [line.strip() for line in body.strip().split("\n") if line.strip()]

    if not lines:
        return None, None

    url = lines[0]
    category = lines[1] if len(lines) > 1 else None

    return url, category


def is_valid_feed(url: str) -> bool:
    """Check that a URL serves an RSS or Atom feed over HTTP(S).

    feedparser also reads a local path or a literal XML document, either of which an email could carry instead of a
    URL.
    """
    try:
        if urlparse(url).scheme not in {"http", "https"}:
            logger.warning(f"{url} is not an HTTP(S) URL")
            return False

        fetch_feed(url)
    except Exception as e:
        logger.error(f"Error validating feed {url}: {e}")
        return False

    return True


def add_feed_to_file(file_path: Path, url: str, category: str | None = None) -> None:
    """Append a feed URL to the feeds file, with optional category comment.

    If category is provided and already exists in the file, the URL is added after
    the last URL in that category. If the category doesn't exist, a new category
    section is created. If no category is provided, the URL is added to "uncategorized".
    """
    # Read existing file content
    if not file_path.exists():
        file_path.touch()

    with Path.open(file_path) as f:
        lines = f.readlines()

    # Default to "uncategorized" if no category provided
    if not category:
        category = "uncategorized"

    # Find if category already exists
    category_comment = f"# {category}\n"
    category_index = -1

    for i, line in enumerate(lines):
        if line == category_comment:
            category_index = i
            break

    if category_index == -1:
        # Category doesn't exist - add new section at end
        with Path.open(file_path, "a") as f:
            f.write(f"\n\n{category_comment}{url}\n")
    else:
        # Category exists - insert after the last URL in it, before the blank line or comment that ends it
        insert_index = category_index + 1
        for i in range(category_index + 1, len(lines)):
            if lines[i].startswith("#"):
                break
            if lines[i].strip():
                insert_index = i + 1

        # The line before may be the file's last, without a line break of its own
        if not lines[insert_index - 1].endswith("\n"):
            lines[insert_index - 1] += "\n"

        lines.insert(insert_index, f"{url}\n")

        # Write back the entire file
        with Path.open(file_path, "w") as f:
            f.writelines(lines)


def process_email(msg: MailMessage) -> None:
    logger.info(f"Processing email {msg.uid}")

    if msg.uid is None:
        logger.warning(f"Email {msg} has no UID")

    body_text = msg.text or msg.html
    if not body_text:
        logger.warning(f"Email {msg.uid} has no valid body")
        return

    url, category = parse_email_body(body_text)
    if not url:
        logger.warning(f"Email {msg.uid} has no valid URL")
        return

    if url in read_feeds_file(FEEDS_FILE_PATH):
        logger.info(f"Feed {url} is already in the feeds file")
        return

    if not is_valid_feed(url):
        logger.warning(f"URL {url} is not a valid feed")
        return

    logger.info(f"Adding feed {url} with category '{category}' to feeds file")
    add_feed_to_file(FEEDS_FILE_PATH, url, category)


def check_emails() -> None:
    """Check IMAP mailbox for new feed URLs and add them to feeds file."""
    if not IMAP_HOST or not IMAP_USER or not IMAP_PASSWORD:
        logger.warning("IMAP not configured, skipping email check")
        return

    with MailBox(host=IMAP_HOST, port=IMAP_PORT).login(IMAP_USER, IMAP_PASSWORD) as mailbox:
        mailbox.folder.set(IMAP_MAILBOX)

        # Fetching a message marks it as read.
        messages = list(mailbox.fetch(criteria="UNSEEN"))
        if not messages:
            logger.debug("No unread emails found")
            return

        for msg in messages:
            process_email(msg)


def create_state_table() -> None:
    with get_db_cursor() as cursor:
        cursor.execute(SQL_CREATE_STATE_TABLE)
        cursor.execute(SQL_CREATE_SEEN_TABLE)


def check_feeds() -> None:
    feed_urls = read_feeds_file(FEEDS_FILE_PATH)

    for feed_url in feed_urls:
        logger.info(f"Processing feed {feed_url}")
        try:
            feed = Feed.from_url(feed_url)
        except Exception as e:
            logger.error(f"Error fetching or parsing feed {feed_url}: {e}")
            sentry_sdk.capture_exception(e)
            continue

        logger.info(f"Feed title: {feed.metadata.title}")

        try:
            feed.process()
        except Exception as e:
            logger.error(f"Error processing feed {feed.metadata.title}: {e}")
            sentry_sdk.capture_exception(e)
            continue


def job() -> None:
    try:
        check_emails()
    except Exception as e:
        logger.error(f"Error checking IMAP emails: {e}")
        sentry_sdk.capture_exception(e)

    try:
        check_feeds()
    except Exception as e:
        logger.error(f"Error checking feeds: {e}")
        sentry_sdk.capture_exception(e)


def main() -> None:
    """Run one check and return. meed does not schedule itself: whatever starts it decides how often."""
    logger.info("Starting meed...")
    logger.info(f"Using User-Agent: {USER_AGENT}")
    # feedparser, smtplib and imaplib open their sockets without a timeout of their own, so they use this one.
    socket.setdefaulttimeout(NETWORK_TIMEOUT)
    create_state_table()
    job()


if __name__ == "__main__":
    # Configure logging with custom JSON formatter
    handler = logging.StreamHandler()
    handler.setFormatter(MeedJSONFormatter())

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(handler)

    if SENTRY_DSN:
        sentry_sdk.init(dsn=SENTRY_DSN)

    main()
