.PHONY: lint check test

lint:
	uv run ruff format .
	uv run ruff check --fix .
	uv run ty check

# What has to pass before a deploy. Unlike lint it changes no file.
check:
	uv lock --check
	uv run ruff format --check .
	uv run ruff check .
	uv run ty check
	uv run pytest

test:
	uv run pytest
