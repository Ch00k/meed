# meed

Email notifications for RSS/Atom feeds.

**meed** monitors RSS and Atom feeds on a schedule and sends email notifications for new entries, tracking state in a
SQLite database.

## Features

- **Multiple feed support**: Monitor blogs, podcasts, YouTube channels, and any RSS/Atom feed
- **Email-based feed addition**: Add feeds by sending emails (requires IMAP configuration)
- **Hourly checks**: Runs as a scheduled [Fly.io](https://fly.io) Machine that checks once and exits
- **Chronological delivery**: New entries are emailed oldest-first to preserve reading order
- **Robust parsing**: Handles malformed feeds gracefully with intelligent fallbacks
- **State tracking**: SQLite database prevents duplicate notifications
- **HTML emails**: Rich email content with links and summaries

## Requirements

- A [Fly.io](https://fly.io) account and `flyctl`
- SMTP server access for sending emails

## Deployment

**meed** does one check per run and exits. On Fly.io it runs as a single Machine with an hourly schedule: Fly starts it
roughly once an hour (at a time of its choosing, not on the hour), and it stops when **meed** exits, so only the seconds
it runs are billed. The feed list and the state database live on a volume mounted at `/data`.

There is no `fly.toml` on purpose. `fly deploy` manages only Machines that belong to a process group in `fly.toml`, does
not keep a Machine's schedule, and creates Machines that restart when their process exits. Instead, every release tag
replaces the scheduled Machine with a new one (the `deploy` job in `.github/workflows/ci.yml`), which runs a check
straight away and then hourly.

### One-time setup

1. Create the app and the volume, and store the configuration (see Environment Variables below) as secrets. Secrets
   reach a Machine when it starts, so `--stage` is enough: the next scheduled run picks them up.
   ```bash
   fly apps create meed
   fly volumes create meed_data --app meed --region fra --size 1
   fly secrets set --app meed --stage MEED_SMTP_HOST=... MEED_SMTP_USER=... MEED_SMTP_PASSWORD=... \
       MEED_EMAIL_FROM=... MEED_EMAIL_TO=...
   ```

2. Put `feeds.txt` (and, when moving an existing installation, its `state.db`) on the volume, from a temporary Machine.
   Without a `state.db`, the first run records every feed's current entries and sends nothing.
   ```bash
   fly machine run . --app meed --region fra --name seed --volume meed_data:/data --restart no sleep 900
   ```
   flyctl finds a Machine by its ID only, not by its name: take the ID from the output above (or `fly machine list
   --app meed`).
   ```bash
   fly ssh sftp put feeds.txt /data/feeds.txt --app meed --machine <seed machine id>
   fly ssh sftp put state.db /data/state.db --app meed --machine <seed machine id>
   fly ssh console --app meed --machine <seed machine id> -C "chown -R meed:meed /data"
   fly machine destroy <seed machine id> --app meed --force
   ```
   meed runs as the user `meed`, and SFTP writes the files as root, hence the `chown`.

3. Give CI a deploy token, then release (below): the first release's `deploy` job creates the scheduled Machine.
   ```bash
   fly tokens create deploy --app meed | gh secret set FLY_API_TOKEN
   ```

### Releasing

A release is a version tag. CI (`.github/workflows/ci.yml`) runs `make check` on every push, and on a tag such as
`0.4.0` it also builds the image and deploys it, refusing a tag that is not the version in `pyproject.toml`:

```bash
# Bump version in pyproject.toml, commit, then:
git tag 0.4.0
git push origin main 0.4.0
```

Fly snapshots the volume daily and keeps the snapshots for 5 days.

## Configuration

### Environment Variables

**meed** is configured via environment variables, which on Fly.io are the app's secrets:

| Variable | Default | Description |
|----------|---------|-------------|
| `MEED_SMTP_HOST` | `127.0.0.1` | SMTP server hostname |
| `MEED_SMTP_PORT` | `465` | SMTP server port |
| `MEED_SMTP_USER` | `user` | SMTP authentication username |
| `MEED_SMTP_PASSWORD` | `password` | SMTP authentication password |
| `MEED_EMAIL_FROM` | `meed@example.com` | Sender email address |
| `MEED_EMAIL_TO` | `my@e.mail` | Recipient email address |
| `MEED_IMAP_HOST` | _(none)_ | Optional IMAP server hostname for email-based feed addition (e.g., `imap.fastmail.com`) |
| `MEED_IMAP_PORT` | `993` | IMAP server port |
| `MEED_IMAP_USER` | _(none)_ | Optional IMAP username/email for authentication |
| `MEED_IMAP_PASSWORD` | _(none)_ | Optional IMAP password or app-specific password |
| `MEED_IMAP_MAILBOX` | `INBOX.meed` | IMAP mailbox/folder name to monitor for feed addition emails |
| `MEED_SENTRY_DSN` | _(none)_ | Optional Sentry DSN for error tracking |
| `MEED_FEEDS_FILE_PATH` | `feeds.txt` | Feed list; the Docker image sets it to `/data/feeds.txt` |
| `MEED_STATE_DB_PATH` | `state.db` | State database; the Docker image sets it to `/data/state.db` |

### Feed Configuration

Create a `feeds.txt` file with one feed URL per line. Lines starting with `#` are treated as comments:

```
# Blogs
https://daringfireball.net/feeds/articles
https://astral.sh/blog/rss.xml

# YouTube
https://www.youtube.com/feeds/videos.xml?channel_id=UCy0tKL1T7wFoYcxCe0xjN6Q

# Podcasts
https://changelog.com/podcast/feed
```

### Adding Feeds via Email (Optional)

If you configure IMAP credentials, you can add feeds by sending an email to a designated mailbox. **meed** will check
this mailbox on each run, validate the feed URLs, and automatically add them to `feeds.txt`.

**Email format:**
```
https://example.com/feed.xml
Tech News
```

- **Line 1**: Feed URL (required)
- **Line 2**: Category name (optional)

**meed** will validate each URL to ensure it's a valid RSS/Atom feed before adding it. Invalid URLs or emails are logged
and marked as read.

## How It Works

1. **First run**: **meed** reads all feeds and stores their current state in the database. No emails are sent.
2. **Subsequent runs**: **meed** compares the current feed state with the stored state and sends emails for new entries.
3. **Email delivery**: New entries are sent in chronological order (oldest first) to preserve reading order.
4. **State updates**: After successful processing, the database is updated with the latest feed state.

## Development

### Running Tests

```bash
make test
```

The test suite includes comprehensive tests covering:
- New entry detection and ordering
- Feed format compatibility (RSS 2.0, Atom 1.0)
- Error handling (network errors, SMTP failures, malformed feeds)
- State persistence and database integrity
- Unicode and HTML content handling
- Email parsing and feed addition via IMAP

### Linting and Type Checking

```bash
make lint
```

This runs `ruff` for linting/formatting and `ty` for static type checking. `make check` runs everything CI does
before a deploy without changing any file: the lockfile check, `ruff`, `ty` and the tests.
