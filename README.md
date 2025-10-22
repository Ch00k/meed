# meed

Email notifications for RSS/Atom feeds.

**meed** monitors RSS and Atom feeds on a schedule and sends email notifications for new entries, tracking state in a
SQLite database.

## Features

- **Multiple feed support**: Monitor blogs, podcasts, YouTube channels, and any RSS/Atom feed
- **Scheduled checks**: Cron-based scheduling (default: every 4 hours)
- **Chronological delivery**: New entries are emailed oldest-first to preserve reading order
- **Robust parsing**: Handles malformed feeds gracefully with intelligent fallbacks
- **State tracking**: SQLite database prevents duplicate notifications
- **HTML emails**: Rich email content with links and summaries

## Requirements

- Docker and Docker Compose
- SMTP server access for sending emails

## Quick Start

1. Copy the example environment file and configure your settings:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your SMTP credentials and email addresses

3. Create a `data/` directory and a `feeds.txt` file in it with your feed URLs (see Feed Configuration below)

4. Start **meed**:
   ```bash
   docker compose up -d
   ```

For easier deployment with automatic updates, consider using [oar](https://github.com/oar-cd/oar), which provides a simple way to deploy and manage **meed** in production.

## Configuration

### Environment Variables

**meed** is configured via environment variables in the `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `MEED_SMTP_HOST` | `127.0.0.1` | SMTP server hostname |
| `MEED_SMTP_PORT` | `465` | SMTP server port |
| `MEED_SMTP_USER` | `user` | SMTP authentication username |
| `MEED_SMTP_PASSWORD` | `password` | SMTP authentication password |
| `MEED_EMAIL_FROM` | `meed@example.com` | Sender email address |
| `MEED_EMAIL_TO` | `my@e.mail` | Recipient email address |
| `MEED_CRON_SCHEDULE` | `0 */4 * * *` | Cron expression for check schedule |
| `MEED_TIMEZONE` | `UTC` | Timezone for scheduling (e.g., `Europe/Amsterdam`, `America/New_York`) |
| `MEED_SENTRY_DSN` | _(none)_ | Optional Sentry DSN for error tracking |

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

The test suite includes 30 comprehensive tests covering:
- New entry detection and ordering
- Feed format compatibility (RSS 2.0, Atom 1.0)
- Error handling (network errors, SMTP failures, malformed feeds)
- State persistence and database integrity
- Unicode and HTML content handling

### Linting and Type Checking

```bash
make lint
```

This runs `ruff` for linting/formatting and `mypy` for static type checking.

## License

Public Domain (Unlicense)
