FROM ghcr.io/astral-sh/uv:python3.13-alpine

# Install timezone data to avoid tzlocal warnings
RUN apk add --no-cache tzdata

RUN --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

COPY meed.py ./

ENV PATH=/.venv/bin:$PATH

ENTRYPOINT []
CMD ["python", "meed.py"]
