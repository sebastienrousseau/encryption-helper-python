# SPDX-License-Identifier: Apache-2.0
#
# Developer entry points. Every target here is what CI runs, so a green
# `make check` locally means a green pipeline.

.POSIX:
.DEFAULT_GOAL := help
PY := poetry run

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Install dependencies and git hooks
	poetry install
	$(PY) pre-commit install

.PHONY: check
check: lint types test security ## Everything CI runs

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

.PHONY: fuzz
fuzz: ## Fuzz the parsers (no engine required)
	cd fuzz && $(PY) python run_fuzz.py --iterations 50000

.PHONY: bench
bench: ## Indicative benchmarks, not a gate
	$(PY) python benches/bench_crypto.py --quick

.PHONY: examples
examples: ## Run every example
	@for f in examples/*.py; do echo "--- $$f"; $(PY) python "$$f" || exit 1; done

.PHONY: sbom
sbom: ## Generate a CycloneDX SBOM
	@# Installed on demand rather than declared as a dev dependency: its own
	@# Python constraint is narrower than this project's floor.
	mkdir -p dist
	$(PY) pip install --quiet cyclonedx-bom
	$(PY) python -m cyclonedx_py environment \
		--output-format JSON --output-file dist/encryption-helper.cdx.json

.PHONY: build
build: ## Build sdist and wheel, then validate
	$(PY) python -m build
	$(PY) twine check --strict dist/*

.PHONY: verify
verify: ## Full release-candidate gate in a clean environment
	./scripts/verify-release-candidate.sh

.PHONY: clean
clean: ## Remove build and cache artefacts
	rm -rf build dist .coverage .pytest_cache .ruff_cache .mypy_cache .hypothesis
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
