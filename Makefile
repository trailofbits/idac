TESTS :=

# If the user selects a specific test pattern to run, set pytest to fail fast
# and only run tests that match the pattern. Otherwise, run the full suite.
ifneq ($(TESTS),)
	TEST_ARGS := -x -k $(TESTS)
else
	TEST_ARGS :=
endif

.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: dev
dev:
	uv sync --group dev

.PHONY: run
run:
	uv run idac $(ARGS)

.PHONY: lint
lint:
	uv sync --group lint
	uv run ruff format --check
	uv run ruff check

.PHONY: format
format:
	uv sync --group lint
	uv run ruff format
	uv run ruff check --fix

.PHONY: test
test:
	uv sync --group test
	uv run pytest -q $(T) $(TEST_ARGS)

.PHONY: audit
audit:
	uv audit --locked

.PHONY: doc
doc:
	@echo "No generated documentation set up"

.PHONY: build
build:
	uv build

.PHONY: check
check: lint test audit
