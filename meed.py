import logging
import signal
import smtplib
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

import environs
import feedparser
import sentry_sdk
from apscheduler.events import EVENT_JOB_ERROR
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)

env = environs.Env()

FEEDS_FILE_PATH = env.path("MEED_FEEDS_FILE_PATH")
STATE_DB_PATH = env.path("MEED_STATE_DB_PATH")

SMTP_HOST = env.str("MEED_SMTP_HOST")
SMTP_PORT = env.int("MEED_SMTP_PORT")
SMTP_USER = env.str("MEED_SMTP_USER")
SMTP_PASSWORD = env.str("MEED_SMTP_PASSWORD")

EMAIL_FROM = env.str("MEED_EMAIL_FROM")
EMAIL_TO = env.str("MEED_EMAIL_TO")

CRON_SCHEDULE = env.str("MEED_CRON_SCHEDULE", "0 */4 * * *")  # Every 4 hours

SENTRY_DSN = env.str("MEED_SENTRY_DSN", None)

SQL_CREATE_STATE_TABLE = "CREATE TABLE IF NOT EXISTS feeds (id TEXT, last_checked_at DATETIME, last_entry_id TEXT)"
SQL_GET_STATE = "SELECT last_checked_at, last_entry_id FROM feeds WHERE id = ?"
SQL_CREATE_STATE = "INSERT INTO feeds (id, last_checked_at, last_entry_id) VALUES (?, datetime('now'), ?)"
SQL_UPDATE_STATE = "UPDATE feeds SET last_checked_at = datetime('now'), last_entry_id = ? WHERE id = ?"


@contextmanager
def get_db_cursor():
    conn = sqlite3.connect(STATE_DB_PATH)
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    finally:
        conn.close()


class FeedEntry(BaseModel):
    id: str | None = None
    title: str | None = None
    link: str | None = None
    summary: str | None = None
    published: str | None = None

    def send_notification(self, feed_title: str) -> None:
        msg = MIMEText(f"{self.link}<br><br>{self.summary}", "html", "utf-8")
        msg["From"] = f"{feed_title} <{EMAIL_FROM}>"
        msg["To"] = EMAIL_TO
        msg["Subject"] = self.title or "New entry"

        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())


class FeedMetadata(BaseModel):
    id: str
    title: str | None = None


class Feed(BaseModel):
    metadata: FeedMetadata = Field(alias="feed")
    entries: list[FeedEntry] = []

    @model_validator(mode="after")
    def sort_entries(self) -> "Feed":
        if self.entries:
            # Sort entries by published date, newest first, None values last
            self.entries.sort(key=lambda e: (e.published is not None, e.published), reverse=True)
        return self

    @classmethod
    def from_url(cls, url: str) -> "Feed":
        parsed_feed = feedparser.parse(url)
        return cls(**parsed_feed)

    def get_new_entries(self, last_id: str | None) -> list[FeedEntry]:
        if not last_id:
            return self.entries

        new_entries = []
        for entry in self.entries:
            if entry.id == last_id:
                break

            new_entries.append(entry)

        # Sort new entries by published date, oldest first, None values last
        return sorted(new_entries, key=lambda e: (e.published is not None, e.published))

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
            title = entry.title or "No Title"
            logger.info(f"Sending notification for entry {title} ({entry.link})")
            entry.send_notification(self.metadata.title or "No Title")

        if new_entries:
            logger.info(f"Updating state for feed {self.metadata.title}")
            self.update_state()

    def is_known(self) -> bool:
        return self.get_state() != (None, None)

    def get_state(self) -> tuple[datetime | None, str | None]:
        with get_db_cursor() as cursor:
            cursor.execute(SQL_GET_STATE, (self.metadata.id,))
            row = cursor.fetchone()

        return (datetime.fromisoformat(row[0]), row[1]) if row else (None, None)

    def create_state(self) -> None:
        if self.is_known():
            return

        with get_db_cursor() as cursor:
            cursor.execute(SQL_CREATE_STATE, (self.metadata.id, self.entries[0].id if self.entries else None))

    def update_state(self) -> None:
        with get_db_cursor() as cursor:
            cursor.execute(SQL_UPDATE_STATE, (self.entries[0].id if self.entries else None, self.metadata.id))


def read_feeds_file(file_path: Path) -> list:
    if not file_path.exists():
        logger.warning(f"Feeds file {file_path} does not exist.")
        return []

    with open(file_path) as f:
        feed_urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    return feed_urls


def create_state_table() -> None:
    with get_db_cursor() as cursor:
        cursor.execute(SQL_CREATE_STATE_TABLE)


def check_feeds() -> None:
    feed_urls = read_feeds_file(FEEDS_FILE_PATH)

    for feed_url in feed_urls:
        logger.info(f"Processing feed {feed_url}")
        feed = Feed.from_url(feed_url)
        logger.info(f"Feed title: {feed.metadata.title}")
        feed.process()


def sentry_listener(event):
    if event.exception:
        sentry_sdk.capture_exception(event.exception)


def main(run_once: bool = False) -> None:
    logger.info("Starting meed...")
    create_state_table()

    if run_once:
        check_feeds()
        return

    logger.info(f"Creating schedule with crontab '{CRON_SCHEDULE}'")

    scheduler = BlockingScheduler()
    scheduler.add_listener(sentry_listener, mask=EVENT_JOB_ERROR)
    scheduler.add_job(check_feeds, CronTrigger.from_crontab(CRON_SCHEDULE))

    def signal_handler_scheduler(signum: int, _: Any) -> None:
        scheduler.shutdown()

    for s in [signal.SIGHUP, signal.SIGINT, signal.SIGTERM]:
        signal.signal(s, signal_handler_scheduler)

    scheduler.start()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if SENTRY_DSN:
        sentry_sdk.init(dsn=SENTRY_DSN)

    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        run_once = True
    else:
        run_once = False

    main(run_once=run_once)
