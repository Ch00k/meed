"""Convert the SQLite state database of an earlier meed release, state.db, to the state object, state.json.

    uv run python -m scripts.convert_state state.db state.json

A feed's seen entries stay seen. A feed with none but a last entry ID, the newest entry emailed, is fetched: that entry
and every entry the feed lists after it count as seen. When it has left the feed, which entries are new cannot be told,
so it and all the feed's entries count as seen. A feed with neither was empty when meed first checked it.
"""

import socket
import sqlite3
import sys
from pathlib import Path

from meed import NETWORK_TIMEOUT, Feed, FeedEntry, format_state, title_entry_id


def released_entry_ids(entry: FeedEntry) -> set[str]:
    """The IDs a release may have stored for the entry.

    meed 0.3.0 identified an entry with neither an ID nor a link by its bare title.
    """
    if entry.id == title_entry_id(entry.title, entry.published):
        return {entry.id, entry.title}

    return {entry.id}


def seen_from_last_entry_id(feed: Feed, last_entry_id: str) -> set[str]:
    entry_ids = [entry.id for entry in feed.entries]
    if last_entry_id in entry_ids:
        return set(entry_ids[entry_ids.index(last_entry_id) :])

    # Only when no entry has it as its ID: an entry identified by title can share its title with another's ID.
    for index, entry in enumerate(feed.entries):
        if last_entry_id in released_entry_ids(entry):
            return set(entry_ids[index:])

    print(f"Last sent entry {last_entry_id} is no longer in feed {feed.metadata.id}", file=sys.stderr)
    return {last_entry_id, *entry_ids}


def convert(db_path: Path) -> dict[str, set[str]]:
    """The state of every feed in the database, leaving out a feed that needs fetching and cannot be fetched."""
    conn = sqlite3.connect(db_path)
    try:
        feeds = conn.execute("SELECT id, last_entry_id FROM feeds").fetchall()
        # meed 0.3.0 kept only the feeds table.
        has_seen_entries = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'seen_entries'"
        ).fetchone()
        seen_rows = conn.execute("SELECT feed_id, entry_id FROM seen_entries").fetchall() if has_seen_entries else []
    finally:
        conn.close()

    seen: dict[str, set[str]] = {}
    for feed_id, entry_id in seen_rows:
        seen.setdefault(feed_id, set()).add(entry_id)

    state: dict[str, set[str]] = {}
    for feed_id, last_entry_id in feeds:
        if feed_id in seen:
            state[feed_id] = seen[feed_id]
        elif last_entry_id is None:
            state[feed_id] = set()
        else:
            try:
                feed = Feed.from_url(feed_id)
            except Exception as e:
                # Left out, the feed is new to meed: its first check records its entries and sends none.
                print(f"Leaving out feed {feed_id}, which cannot be fetched: {e}", file=sys.stderr)
                continue
            state[feed_id] = seen_from_last_entry_id(feed, last_entry_id)

    return state


def main() -> None:
    db_path, json_path = (Path(arg) for arg in sys.argv[1:])
    # A feed that stalls then fails like one that cannot be fetched.
    socket.setdefaulttimeout(NETWORK_TIMEOUT)
    json_path.write_text(format_state(convert(db_path)))


if __name__ == "__main__":
    main()
