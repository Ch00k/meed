# syntax=docker/dockerfile:1
# The digest pins what the tag names today; the tag alone moves with every Debian and Python patch release.
FROM ghcr.io/astral-sh/uv:0.13.9-python3.14-trixie-slim@sha256:da0f1f04404173d7d2fa158112e09624d5a80262efa86c89882b68389dfd44eb

# Compiled at build time: the app's user cannot write bytecode into /app, and every run would otherwise compile
# everything it imports from source.
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1
WORKDIR /app

# COPY instead of --mount=type=bind so that Docker includes file contents in the layer cache key; a bind mount is not
# part of it, and a changed uv.lock would leave a stale .venv. meed is a single module, not a package, so the
# dependencies are all there is to install.
COPY uv.lock pyproject.toml /app/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-install-project --locked --no-dev

COPY meed.py /app/

ENV PATH=/app/.venv/bin:$PATH

RUN python -m compileall -q /app/meed.py

# The volume holding the feed list and the state database is mounted at /data.
ENV MEED_FEEDS_FILE_PATH=/data/feeds.txt
ENV MEED_STATE_DB_PATH=/data/state.db

# meed never needs root, and the volume it writes to is the only thing it must own. /data is created here so the mount
# point belongs to the user before the volume is attached over it.
RUN useradd --create-home --uid 10001 meed \
    && mkdir -p /data \
    && chown meed:meed /data

USER meed

# One check, then exit: the Machine stops until Fly starts it again.
CMD ["python", "meed.py"]
