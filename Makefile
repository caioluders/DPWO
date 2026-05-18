PYTHON ?= python3
VENV := .venv
BIN := $(VENV)/bin
PIP := $(BIN)/pip
PYTEST := $(BIN)/pytest
PYINSTALLER := $(BIN)/pyinstaller

# Platform-specific data separator for PyInstaller
ifeq ($(OS),Windows_NT)
	SEP := ;
	CLI_NAME := dpwo.exe
	GUI_NAME := dpwo-gui.exe
else
	SEP := :
	CLI_NAME := dpwo
	GUI_NAME := dpwo-gui
endif

.PHONY: all venv install install-dev test build build-cli build-gui run run-gui clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

all: test build ## Run tests and build all binaries

venv: $(BIN)/activate ## Create virtual environment

$(BIN)/activate:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

install: venv ## Install runtime dependencies
	$(PIP) install -r requirements.txt

install-dev: install ## Install runtime + build dependencies
	$(PIP) install -r requirements-dev.txt
	$(PIP) install pytest

test: install ## Run test suite
	$(BIN)/pytest tests/ -v

build: build-cli build-gui ## Build CLI and GUI binaries

build-cli: install-dev ## Build CLI standalone binary
	$(BIN)/pyinstaller --onefile --console --name dpwo \
		--add-data "plugins$(SEP)plugins" dpwo.py
	@echo "Built: dist/$(CLI_NAME)"

build-gui: install-dev ## Build GUI standalone binary
	$(BIN)/pyinstaller --onefile --windowed --name dpwo-gui \
		--add-data "plugins$(SEP)plugins" gui.py
	@echo "Built: dist/$(GUI_NAME)"

run: install ## Run CLI
	$(BIN)/python dpwo.py $(ARGS)

run-gui: install ## Run GUI
	$(BIN)/python gui.py

clean: ## Remove venv, build artifacts, and caches
	rm -rf $(VENV) build/ dist/ *.spec __pycache__ .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
