import logging
import signal
import smtplib
import sqlite3
import sys
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from email.mime.text import MIMEText
from pathlib import Path
from types import FrameType
from typing import Any

import environs
import feedparser
import sentry_sdk
from apscheduler.events import EVENT_JOB_ERROR, JobExecutionEvent
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from dateutil import parser as date_parser
from json_log_formatter import BUILTIN_ATTRS, JSONFormatter
from pydantic import BaseModel, Field, model_validator

BUILTIN_ATTRS.add("taskName")

logger = logging.getLogger(__name__)


class MeedJSONFormatter(JSONFormatter):
    def extra_from_record(self, record: logging.LogRecord) -> dict:
        return {
            attr_name: record.__dict__[attr_name] for attr_name in record.__dict__ if attr_name not in BUILTIN_ATTRS
        }

    def json_record(self, message: str, extra: dict, record: logging.LogRecord) -> dict:
        new_extra: dict[str, Any] = {}

        new_extra["timestamp"] = datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="microseconds") + "Z"
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


env = environs.Env()

FEEDS_FILE_PATH = env.path("MEED_FEEDS_FILE_PATH", Path("feeds.txt"))
STATE_DB_PATH = env.path("MEED_STATE_DB_PATH", Path("state.db"))

SMTP_HOST = env.str("MEED_SMTP_HOST", "127.0.0.1")
SMTP_PORT = env.int("MEED_SMTP_PORT", 465)
SMTP_USER = env.str("MEED_SMTP_USER", "user")
SMTP_PASSWORD = env.str("MEED_SMTP_PASSWORD", "password")

EMAIL_FROM = env.str("MEED_EMAIL_FROM", "meed@example.com")
EMAIL_TO = env.str("MEED_EMAIL_TO", "my@e.mail")

CRON_SCHEDULE = env.str("MEED_CRON_SCHEDULE", "0 */4 * * *")

SENTRY_DSN = env.str("MEED_SENTRY_DSN", None)

SQL_CREATE_STATE_TABLE = "CREATE TABLE IF NOT EXISTS feeds (id TEXT, last_checked_at DATETIME, last_entry_id TEXT)"
SQL_GET_STATE = "SELECT last_checked_at, last_entry_id FROM feeds WHERE id = ?"
SQL_CREATE_STATE = "INSERT INTO feeds (id, last_checked_at, last_entry_id) VALUES (?, datetime('now'), ?)"
SQL_UPDATE_STATE = "UPDATE feeds SET last_checked_at = datetime('now'), last_entry_id = ? WHERE id = ?"


@contextmanager
def get_db_cursor() -> Generator[sqlite3.Cursor, None, None]:
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

        # Determine published date
        published_date = value.get("published") or value.get("updated") or value.get("created")
        if not published_date:
            logger.warning(f"FeedEntry {value['id']} has no published date, skipping entry")
            raise InvalidFeedEntryError("FeedEntry must have a published, updated, or created date")

        # Parse published date
        value["published"] = date_parser.parse(published_date)

        return value

    def send_notification(self, feed_title: str) -> None:
        msg = MIMEText(f"{self.link}<br><br>{self.summary}", "html", "utf-8")
        msg["From"] = f'"{feed_title}" <{EMAIL_FROM}>'
        msg["To"] = EMAIL_TO
        msg["Subject"] = self.title

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
    def sort_entries(self) -> "Feed":
        if self.entries:
            # Sort entries by published date, newest first
            self.entries.sort(key=lambda e: e.published, reverse=True)
        return self

    @classmethod
    def from_url(cls, url: str) -> "Feed":
        parsed_feed = feedparser.parse(url)

        if "feed" in parsed_feed:
            logger.info(f"Replacing feed ID with URL for feed {url}")
            parsed_feed["feed"]["id"] = url  # pyright: ignore[reportCallIssue,reportArgumentType]

            if not parsed_feed["feed"].get("title"):  # pyright: ignore[reportAttributeAccessIssue]
                logger.warning(f"Feed {url} has no title, using URL as title")
                parsed_feed["feed"]["title"] = url  # pyright: ignore[reportCallIssue,reportArgumentType]
        else:
            logger.warning(f"Feed {url} has no feed metadata, using URL as ID and title")
            parsed_feed["feed"] = {"id": url, "title": url}

        return cls(**parsed_feed)  # pyright: ignore[reportArgumentType]

    def get_new_entries(self, last_id: str | None) -> list[FeedEntry]:
        if not last_id:
            return self.entries

        new_entries = []
        for entry in self.entries:
            if entry.id == last_id:
                break

            new_entries.append(entry)

        # Sort new entries by published date, oldest first
        return sorted(new_entries, key=lambda e: e.published)

    def process(self) -> None:
        if not self.is_known():
            logger.info(f"Feed {self.metadata.title} is new, creating state")
            self.create_state()
            return

        logger.info(f"Feed {self.metadata.title} is known, checking for new entries")

        _, last_entry_id = self.get_state()
        logger.info(f"Last known entry ID: {last_entry_id}")

        new_entries = self.get_new_entries(last_entry_id)

        if new_entries:
            logger.info(f"Found {len(new_entries)} new entries")
        else:
            logger.info("No new entries found")

        for entry in new_entries:
            title = entry.title
            logger.info(f"Sending notification for entry {title} ({entry.link})")
            entry.send_notification(self.metadata.title)

        if new_entries:
            logger.info(f"Updating state for feed {self.metadata.title}")
            self.update_state()

    def is_known(self) -> bool:
        return self.get_state() != (None, None)

    def get_state(self) -> tuple[datetime | None, str | None]:
        with get_db_cursor() as cursor:
            logger.debug("Executing SQL: %s with params (%s)", SQL_GET_STATE, self.metadata.id)
            cursor.execute(SQL_GET_STATE, (self.metadata.id,))
            row = cursor.fetchone()

        result = (datetime.fromisoformat(row[0]), row[1]) if row else (None, None)
        logger.debug("Fetched state from DB: %s", result)

        return result

    def create_state(self) -> None:
        if self.is_known():
            return

        last_entry = self.entries[0].id if self.entries else None
        with get_db_cursor() as cursor:
            logger.debug("Executing SQL: %s with params (%s, %s)", SQL_CREATE_STATE, self.metadata.id, last_entry)
            cursor.execute(SQL_CREATE_STATE, (self.metadata.id, last_entry))

    def update_state(self) -> None:
        last_entry = self.entries[0].id if self.entries else None

        with get_db_cursor() as cursor:
            logger.debug("Executing SQL: %s with params (%s, %s)", SQL_UPDATE_STATE, last_entry, self.metadata.id)
            cursor.execute(SQL_UPDATE_STATE, (last_entry, self.metadata.id))


def read_feeds_file(file_path: Path) -> list:
    if not file_path.exists():
        logger.warning(f"Feeds file {file_path} does not exist.")
        return []

    with Path.open(file_path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def create_state_table() -> None:
    with get_db_cursor() as cursor:
        cursor.execute(SQL_CREATE_STATE_TABLE)


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
        check_feeds()
    except Exception as e:
        logger.error(f"Error in scheduled job: {e}")
        sentry_sdk.capture_exception(e)


def sentry_listener(event: JobExecutionEvent) -> None:
    if event.exception:
        sentry_sdk.capture_exception(event.exception)


def main(*, run_once: bool = False) -> None:
    logger.info("Starting meed...")
    create_state_table()

    if run_once:
        check_feeds()
        return

    logger.info(f"Creating schedule with crontab '{CRON_SCHEDULE}'")

    scheduler = BlockingScheduler()

    # TODO: This does not seem to work - nothing in Sentry
    scheduler.add_listener(sentry_listener, mask=EVENT_JOB_ERROR)
    scheduler.add_job(job, CronTrigger.from_crontab(CRON_SCHEDULE))

    def signal_handler_scheduler(_: int, __: FrameType | None) -> None:
        scheduler.shutdown()

    for s in [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]:
        signal.signal(s, signal_handler_scheduler)

    scheduler.start()


if __name__ == "__main__":
    # Configure logging with custom JSON formatter
    handler = logging.StreamHandler()
    handler.setFormatter(MeedJSONFormatter())

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(handler)

    if SENTRY_DSN:
        sentry_sdk.init(dsn=SENTRY_DSN)

    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        run_once = True
    else:
        run_once = False

    main(run_once=run_once)
