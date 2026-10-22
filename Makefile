PY ?= python3
export PYTHONPATH := src

.PHONY: check lint test run emulator clean

check: lint test run        ## ruff + pytest (emulator test auto-skips) + the scenario table

lint:
	ruff check src tests
	ruff format --check src tests

test:
	$(PY) -m pytest -q

run:                        ## interpreter only, prints the table
	$(PY) -m rtdb_rules check

emulator:                   ## needs firebase-tools + Java; compares both backends
	$(PY) -m pytest -q tests/test_emulator.py -rs
	$(PY) -m rtdb_rules check --backend both

clean:
	rm -rf .pytest_cache .ruff_cache src/*.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
