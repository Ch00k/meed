import functools
import json
import logging
import smtplib
import socket
import tomllib
import urllib.error
from datetime import UTC, datetime
from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import boto3
import environs
import feedparser
import sentry_sdk
from botocore.config import Config
from imap_tools import MailBox, MailMessageFlags
from json_log_formatter import BUILTIN_ATTRS, JSONFormatter
from pydantic import BaseModel, Field, model_validator

if TYPE_CHECKING:
    from botocore.client import BaseClient
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

# The bucket holding the feed list and the state. `fly storage create` sets BUCKET_NAME, and the AWS_* variables that
# boto3 reads by itself: the credentials and the endpoint, AWS_ENDPOINT_URL_S3. A run needs BUCKET_NAME; importing meed
# does not, which lets scripts/convert_state.py use it without a bucket.
BUCKET_NAME = env.str("BUCKET_NAME", None)
FEEDS_KEY = "feeds.txt"
# For each feed meed knows, the IDs of every entry it has seen: emailed, or already in the feed when meed first checked
# it. A feed with no seen entries was empty when first checked.
STATE_KEY = "state.json"

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

# Seconds a feed fetch, SMTP, IMAP or bucket connection may stall. Without a limit, one stalled connection keeps the
# run, and the Machine it runs on, going forever.
NETWORK_TIMEOUT = 60


# meed is not installed as a package, so there is no package metadata to read its version from.
VERSION = tomllib.loads(Path(__file__).with_name("pyproject.toml").read_text())["project"]["version"]

# Custom User-Agent to identify meed and avoid overly aggressive bot detection
USER_AGENT = f"meed/{VERSION} (+https://github.com/Ch00k/meed)"


@functools.cache
def s3_client() -> BaseClient:
    # Tigris serves a bucket created since February 2025 only at a host name of its own, which boto3 uses only when
    # asked to: with an endpoint URL configured, it otherwise puts the bucket in the path.
    config = Config(s3={"addressing_style": "virtual"}, connect_timeout=NETWORK_TIMEOUT, read_timeout=NETWORK_TIMEOUT)
    return boto3.client("s3", config=config)


def read_object(key: str) -> str | None:
    """The text of an object in the bucket, or None when there is no such object."""
    client = s3_client()
    try:
        response = client.get_object(Bucket=BUCKET_NAME, Key=key)
    except client.exceptions.NoSuchKey:
        return None

    return response["Body"].read().decode()


def write_object(key: str, text: str) -> None:
    s3_client().put_object(Bucket=BUCKET_NAME, Key=key, Body=text.encode())


def read_state() -> dict[str, set[str]]:
    """Every feed meed knows, with the IDs of its entries seen. Without a state object, meed knows no feed."""
    text = read_object(STATE_KEY)
    if text is None:
        logger.warning(f"State object {STATE_KEY} does not exist, every feed is new")
        return {}

    return {feed_id: set(entry_ids) for feed_id, entry_ids in json.loads(text).items()}


def format_state(state: dict[str, set[str]]) -> str:
    return json.dumps({feed_id: sorted(entry_ids) for feed_id, entry_ids in state.items()}, indent=2, sort_keys=True)


def write_state(state: dict[str, set[str]]) -> None:
    write_object(STATE_KEY, format_state(state))


def title_entry_id(title: str, published: datetime) -> str:
    """The ID of an entry with neither an ID nor a link. A title alone repeats, as a daily post's does: the date tells
    such entries apart.
    """
    return f"{title} {published:%Y-%m-%dT%H:%M:%SZ}"


class FeedEntry(BaseModel):
    id: str
    title: str
    summary: str
    link: str
    published: datetime

    @model_validator(mode="before")
    @classmethod
    def ensure_fields(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Determine published date. feedparser parses each date it can read into a UTC time.struct_time.
        published_date = value.get("published_parsed") or value.get("updated_parsed") or value.get("created_parsed")
        if not published_date:
            label = value.get("id") or value.get("link") or value.get("title")
            logger.warning(f"FeedEntry {label} has no published date, skipping entry")
            raise InvalidFeedEntryError("FeedEntry must have a published, updated, or created date")

        value["published"] = datetime(*published_date[:6], tzinfo=UTC)

        # Ensure id field exists
        if not value.get("id"):
            logger.warning("FeedEntry has no ID, attempting to use link or title as ID")
            if value.get("link"):
                logger.warning("Using link as ID")
                value["id"] = value["link"]
            elif value.get("title"):
                logger.warning("Using title and date as ID")
                value["id"] = title_entry_id(value["title"], value["published"])
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
        """The entries not seen yet, oldest first, each ID once.

        Entries with the same date are sent in the reverse of the feed's order, which lists newer entries first.
        """
        new_entries = []
        new_ids = set()
        for entry in reversed(self.entries):
            if entry.id not in seen and entry.id not in new_ids:
                new_ids.add(entry.id)
                new_entries.append(entry)

        return new_entries

    def process(self, state: dict[str, set[str]]) -> None:
        """Email the feed's new entries, recording each in state, which is written back after every change."""
        seen = state.get(self.metadata.id)
        if seen is None:
            # Every entry the feed has now counts as seen: only entries published from here on are new.
            logger.info(f"Feed {self.metadata.title} is new, creating state")
            state[self.metadata.id] = {entry.id for entry in self.entries}
            write_state(state)
            return

        logger.info(f"Feed {self.metadata.title} is known, checking for new entries")

        new_entries = self.get_new_entries(seen)

        if new_entries:
            logger.info(f"Found {len(new_entries)} new entries")
        else:
            logger.info("No new entries found")

        # Each entry is recorded as seen as soon as its email is sent, so a run that fails partway resends nothing.
        for entry in new_entries:
            logger.info(f"Sending notification for entry {entry.title} ({entry.link})")
            entry.send_notification(self.metadata.title)
            seen.add(entry.id)
            write_state(state)


def read_feeds() -> str:
    """The feed list, with Unix line endings, empty when there is none."""
    text = read_object(FEEDS_KEY)
    if text is None:
        logger.warning(f"Feed list {FEEDS_KEY} does not exist")
        return ""

    # A list edited on Windows has CRLF line endings, which would keep add_feed from finding its category headings.
    return text.replace("\r\n", "\n")


def parse_feeds(text: str) -> list[str]:
    lines = [line.strip() for line in text.splitlines()]
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


def add_feed(feeds: str, url: str, category: str | None = None) -> str:
    """Add a feed URL to the feed list, with optional category comment, and return the list.

    If category is provided and already exists in the list, the URL is added after
    the last URL in that category. If the category doesn't exist, a new category
    section is created. If no category is provided, the URL is added to "uncategorized".
    """
    lines = feeds.splitlines(keepends=True)

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
        return f"{feeds}\n\n{category_comment}{url}\n"

    # Category exists - insert after the last URL in it, before the blank line or comment that ends it
    insert_index = category_index + 1
    for i in range(category_index + 1, len(lines)):
        if lines[i].startswith("#"):
            break
        if lines[i].strip():
            insert_index = i + 1

    # The line before may be the list's last, without a line break of its own
    if not lines[insert_index - 1].endswith("\n"):
        lines[insert_index - 1] += "\n"

    lines.insert(insert_index, f"{url}\n")
    return "".join(lines)


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

    feeds = read_feeds()
    if url in parse_feeds(feeds):
        logger.info(f"Feed {url} is already in the feed list")
        return

    if not is_valid_feed(url):
        logger.warning(f"URL {url} is not a valid feed")
        return

    logger.info(f"Adding feed {url} with category '{category}' to the feed list")
    write_object(FEEDS_KEY, add_feed(feeds, url, category))


def check_emails() -> None:
    """Check IMAP mailbox for new feed URLs and add them to the feed list."""
    if not IMAP_HOST or not IMAP_USER or not IMAP_PASSWORD:
        logger.warning("IMAP not configured, skipping email check")
        return

    with MailBox(host=IMAP_HOST, port=IMAP_PORT).login(IMAP_USER, IMAP_PASSWORD) as mailbox:
        mailbox.folder.set(IMAP_MAILBOX)

        # A message is marked as read once handled, so that one a failure, such as an unreachable bucket, keeps from
        # being handled is read again on the next run.
        messages = list(mailbox.fetch(criteria="UNSEEN", mark_seen=False))
        if not messages:
            logger.debug("No unread emails found")
            return

        for msg in messages:
            process_email(msg)
            if msg.uid is not None:
                mailbox.flag(msg.uid, MailMessageFlags.SEEN, value=True)


def check_feeds() -> None:
    feed_urls = parse_feeds(read_feeds())
    state = read_state()

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
            feed.process(state)
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

    # check_feeds handles each feed's errors. What is left, failing to read the feed list or the state from the bucket,
    # fails the run, as a misconfigured bucket must: no feed can be checked.
    check_feeds()


def main() -> None:
    """Run one check and return. meed does not schedule itself: whatever starts it decides how often."""
    if BUCKET_NAME is None:
        msg = "BUCKET_NAME is not set: it names the bucket holding the feed list and the state"
        raise RuntimeError(msg)

    logger.info("Starting meed...")
    logger.info(f"Using User-Agent: {USER_AGENT}")
    # feedparser, smtplib and imaplib open their sockets without a timeout of their own, so they use this one.
    socket.setdefaulttimeout(NETWORK_TIMEOUT)
    job()


if __name__ == "__main__":
    # Configure logging with custom JSON formatter
    handler = logging.StreamHandler()
    handler.setFormatter(MeedJSONFormatter())

    # meed's own debug messages, and the other libraries' from INFO up: botocore's debug messages carry every
    # request and response.
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    if SENTRY_DSN:
        sentry_sdk.init(dsn=SENTRY_DSN)

    main()
