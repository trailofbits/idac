.PHONY: dev lint format test audit check

dev:
	uv sync

lint:
	uv run ruff format --check src/idac tests
	uv run ruff check src/idac tests

format:
	uv run ruff format src/idac tests
	uv run ruff check --fix src/idac tests

test:
	uv run pytest -q

audit:
	uv run pip-audit .

check:
	uv run ruff format --check src/idac tests
	uv run ruff check src/idac tests
	uv run pytest -q
