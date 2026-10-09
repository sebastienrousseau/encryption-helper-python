# SPDX-License-Identifier: Apache-2.0
#
# Developer entry points. Every target here is what CI runs, so a green
# `make check` locally means a green pipeline.

.POSIX:
.DEFAULT_GOAL := help

# Tool invocation prefix. Defaults to `poetry run` where Poetry is installed
# and to the active environment otherwise, so the gate works for contributors
# using pip, venv or uv as well. Override explicitly if needed:
#
#   make PY= check            run against whatever is on PATH
#   make PY="uv run" check     run through uv
#
PY := $(shell command -v poetry >/dev/null 2>&1 && printf '%s' 'poetry run')
PYTHON := $(shell command -v python >/dev/null 2>&1 && printf '%s' python || printf '%s' python3)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Install dependencies and git hooks
	poetry install
	$(PY) pre-commit install

.PHONY: check
check: lint types test security mutation mcp ## Everything CI runs

.PHONY: lint
lint: ## Lint and check formatting
	$(PY) ruff check .
	$(PY) ruff format --check .

.PHONY: fmt
fmt: ## Apply formatting and safe fixes
	$(PY) ruff check --fix .
	$(PY) ruff format .

.PHONY: types
types: ## Type check in strict mode
	$(PY) mypy --strict encryption_helper

.PHONY: test
test: ## Run the suite with the coverage gate
	$(PY) pytest --cov

.PHONY: security
security: ## Static security scan
	$(PY) bandit -c pyproject.toml -r encryption_helper

.PHONY: mcp
mcp: ## Lint, type check and test the MCP server package
	$(PY) ruff check packages/
	$(PY) ruff format --check packages/
	$(PY) mypy --strict packages/encryption-helper-mcp/encryption_helper_mcp
	PYTHONPATH=packages/encryption-helper-mcp $(PY) pytest -q --no-cov \
		packages/encryption-helper-mcp/tests

.PHONY: mutation
mutation: ## Verify the tests detect broken security properties
	$(PY) $(PYTHON) scripts/mutation_check.py

.PHONY: fuzz
fuzz: ## Fuzz the parsers (no engine required)
	cd fuzz && $(PY) $(PYTHON) run_fuzz.py --iterations 50000

.PHONY: bench
bench: ## Indicative benchmarks, not a gate
	$(PY) $(PYTHON) benches/bench_crypto.py --quick

.PHONY: examples
examples: ## Run every example
	@for f in examples/[0-9]*.py; do echo "--- $$f"; $(PY) $(PYTHON) "$$f" || exit 1; done

.PHONY: sbom
sbom: ## Generate a CycloneDX SBOM
	@# Installed on demand rather than declared as a dev dependency: its own
	@# Python constraint is narrower than this project's floor.
	mkdir -p dist
	$(PY) $(PYTHON) -m pip install --quiet cyclonedx-bom
	$(PY) $(PYTHON) -m cyclonedx_py environment \
		--output-format JSON --output-file dist/encryption-helper.cdx.json

.PHONY: build
build: ## Build sdist and wheel, then validate
	$(PY) $(PYTHON) -m build
	$(PY) twine check --strict dist/*

.PHONY: verify
verify: ## Full release-candidate gate in a clean environment
	./scripts/verify-release-candidate.sh

.PHONY: sandbox
sandbox: ## Build the container sandbox image and smoke-test it
	@# Builds from Containerfile with podman or docker, whichever is present,
	@# then runs `capabilities` inside the hardened container as a smoke test.
	@# See docs/SANDBOX.md. Requires network access for the base image.
	./scripts/sandbox.sh --rebuild capabilities

.PHONY: sandbox-examples
sandbox-examples: ## Run the example suite inside the container sandbox
	./scripts/sandbox.sh --rebuild --target examples

.PHONY: clean
clean: ## Remove build and cache artefacts
	rm -rf build dist .coverage .pytest_cache .ruff_cache .mypy_cache .hypothesis
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
