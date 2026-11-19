"""Convert the SQLite state database of an earlier meed release, state.db, to the state object, state.json.

    uv run python -m scripts.convert_state state.db state.json

A feed's seen entries stay seen. A feed with none but a last entry ID, the newest entry emailed, is fetched: that entry
and every entry the feed lists after it count as seen. When it has left the feed, which entries are new cannot be told,
so it and all the feed's entries count as seen. A feed with neither was empty when meed first checked it.
"""

import sqlite3
import sys
from pathlib import Path

from meed import Feed, format_state


def seen_from_last_entry_id(feed: Feed, last_entry_id: str) -> set[str]:
    entry_ids = [entry.id for entry in feed.entries]
    if last_entry_id in entry_ids:
        return set(entry_ids[entry_ids.index(last_entry_id) :])

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
    json_path.write_text(format_state(convert(db_path)))


if __name__ == "__main__":
    main()
