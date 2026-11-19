# meed

Email notifications for RSS/Atom feeds.

**meed** monitors RSS and Atom feeds on a schedule and sends email notifications for new entries, keeping its feed list
and state in an S3-compatible bucket.

## Features

- **Multiple feed support**: Monitor blogs, podcasts, YouTube channels, and any RSS/Atom feed
- **Email-based feed addition**: Add feeds by sending emails (requires IMAP configuration)
- **Hourly checks**: Runs as a scheduled [Fly.io](https://fly.io) Machine that checks once and exits
- **Chronological delivery**: New entries are emailed oldest-first to preserve reading order
- **Robust parsing**: Handles malformed feeds gracefully with intelligent fallbacks
- **State tracking**: Every entry seen is recorded, so no entry is emailed twice
- **HTML emails**: Rich email content with links and summaries

## Requirements

- A [Fly.io](https://fly.io) account and `flyctl`
- SMTP server access for sending emails

## Deployment

**meed** does one check per run and exits. On Fly.io it runs as a single Machine with an hourly schedule: Fly starts it
roughly once an hour (at a time of its choosing, not on the hour), and it stops when **meed** exits, so only the seconds
it runs are billed. The feed list, `feeds.txt`, and the state, `state.json`, are objects in a
[Tigris](https://www.tigrisdata.com) bucket, Fly's S3-compatible object storage, so the Machine has no volume.

There is no `fly.toml` on purpose. `fly deploy` manages only Machines that belong to a process group in `fly.toml`, does
not keep a Machine's schedule, and creates Machines that restart when their process exits. Instead, every release tag
replaces the scheduled Machine with a new one (the `deploy` job in `.github/workflows/ci.yml`), which runs a check
straight away and then hourly.

### One-time setup

1. Create the app and the bucket, and store the configuration (see Environment Variables below) as secrets. Secrets
   reach a Machine when it starts, so `--stage` is enough: the next scheduled run picks them up.
   ```bash
   fly apps create meed
   fly storage create --app meed
   fly secrets set --app meed --stage MEED_SMTP_HOST=... MEED_SMTP_USER=... MEED_SMTP_PASSWORD=... \
       MEED_EMAIL_FROM=... MEED_EMAIL_TO=...
   ```
   `fly storage create` sets the app secrets `BUCKET_NAME`, `AWS_ENDPOINT_URL_S3`, `AWS_ACCESS_KEY_ID` and
   `AWS_SECRET_ACCESS_KEY`, which is all meed needs to reach the bucket.

2. Turn on snapshots for the bucket (see Backups below), with the [Tigris CLI](https://www.tigrisdata.com/docs/cli/),
   which signs in with the Fly account:
   ```bash
   npm install -g @tigrisdata/cli
   tigris login
   tigris buckets enable-snapshots <bucket>
   ```

3. Upload `feeds.txt`, and, when moving an existing installation, its state. Without a `state.json`, the first run
   records every feed's current entries and sends nothing.
   ```bash
   tigris cp feeds.txt t3://<bucket>/feeds.txt
   tigris cp state.json t3://<bucket>/state.json
   ```
   An earlier release kept its state in a SQLite database, `state.db`. Stop that installation, so that it sends nothing
   more, and convert its `state.db` right before the first release here:
   ```bash
   uv run python -m scripts.convert_state state.db state.json
   ```
   A feed's seen entries carry over. A feed with none but the newest entry it emailed is fetched: that entry and every
   entry the feed lists after it count as seen, so only entries published since are sent. When that entry has left the
   feed, all the feed's entries count as seen. A feed that cannot be fetched is left out, with a message, and its first
   check records its entries and sends none.

4. Give CI a deploy token, then release (below): the first release's `deploy` job creates the scheduled Machine.
   ```bash
   fly tokens create deploy --app meed | gh secret set FLY_API_TOKEN
   ```

### Releasing

A release is a version tag. CI (`.github/workflows/ci.yml`) runs `make check` on pushes to `main`, on pull requests
and on tags, and on a tag such as `0.4.0` it also builds the image and deploys it, refusing a tag that is not the
version in `pyproject.toml`. `uv version` sets the version in both `pyproject.toml` and `uv.lock`, which CI checks
against each other:

```bash
uv version 0.4.0
git commit -m "Bump version to 0.4.0" pyproject.toml uv.lock
git tag 0.4.0
git push origin main 0.4.0
```

### Backups

Tigris keeps the history of a bucket with snapshots enabled: every write is kept, so any earlier `feeds.txt` or
`state.json` can be read back, by time or by version, and restored by uploading it again:
```bash
tigris objects list-versions <bucket> --prefix state.json
tigris objects get <bucket> state.json --version-id <version id> --output state.json
```
A bucket from `fly storage create` has snapshots off. Tigris's CLI reference has `tigris buckets enable-snapshots` turn
them on for an existing bucket, while Fly's and some of Tigris's own docs say snapshots can only be enabled when a bucket
is created (`tigris buckets create <bucket> --enable-snapshots`). Without snapshots, an overwritten object is gone.

### Editing the feed list

meed reads `feeds.txt` from the bucket on every run, and adds feeds sent by email to it. To edit it by hand, download it,
edit it and upload it again between runs:
```bash
tigris cp t3://<bucket>/feeds.txt feeds.txt
tigris cp feeds.txt t3://<bucket>/feeds.txt
```

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
| `BUCKET_NAME` | `meed` | Bucket holding `feeds.txt` and `state.json`; set by `fly storage create` |
| `AWS_ENDPOINT_URL_S3` | _(AWS S3)_ | The bucket's S3 endpoint; set by `fly storage create` |
| `AWS_ACCESS_KEY_ID` | _(none)_ | Access key for the bucket; set by `fly storage create` |
| `AWS_SECRET_ACCESS_KEY` | _(none)_ | Secret key for the bucket; set by `fly storage create` |

### Feed Configuration

The feed list, `feeds.txt` in the bucket, has one feed URL per line. Lines starting with `#` are treated as comments:

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
this mailbox on each run, validate the feed URLs, and automatically add them to `feeds.txt` in the bucket.

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

1. **First run of a feed**: **meed** records every entry the feed has as seen. No emails are sent.
2. **Subsequent runs**: every entry **meed** has not seen before is new, whatever its date and wherever the feed
   lists it.
3. **Email delivery**: New entries are sent in chronological order (oldest first) to preserve reading order.
4. **State updates**: Each entry is recorded as seen as soon as its email is sent, so a run that fails partway sends
   nothing twice.

## Development

### Running Tests

```bash
make test
```

The test suite includes comprehensive tests covering:
- New entry detection and ordering
- Feed format compatibility (RSS 2.0, Atom 1.0)
- Error handling (network errors, SMTP failures, malformed feeds)
- State persistence in the bucket (a fake S3, from moto)
- Unicode and HTML content handling
- Email parsing and feed addition via IMAP

### Linting and Type Checking

```bash
make lint
```

This runs `ruff` for linting/formatting and `ty` for static type checking. `make check` runs everything CI does
before a deploy without changing any file: the lockfile check, `ruff`, `ty` and the tests.
