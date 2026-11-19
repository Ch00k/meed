FROM ghcr.io/astral-sh/uv:python3.13-alpine

RUN --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

COPY meed.py ./

ENV PATH=/.venv/bin:$PATH

# The volume holding the feed list and the state database is mounted at /data.
ENV MEED_FEEDS_FILE_PATH=/data/feeds.txt
ENV MEED_STATE_DB_PATH=/data/state.db

# One check, then exit: the container stops until it is started again.
ENTRYPOINT []
CMD ["python", "meed.py"]
