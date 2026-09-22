# ============================================================================
# HYBRIDRECON X - Makefile
# ============================================================================
# Common operations for development and usage
# Made By Parosh
# ============================================================================

.PHONY: help build run install check clean test update

# Default target
help:
	@echo ""
	@echo "HybridRecon X - Makefile Commands"
	@echo "=================================="
	@echo ""
	@echo "  make build       Build Docker image"
	@echo "  make run         Run interactive shell in container"
	@echo "  make scan        Run scan (set TARGET=domain.com)"
	@echo "  make install     Local installation (requires sudo)"
	@echo "  make check       Check tool availability"
	@echo "  make clean       Clean output and temp files"
	@echo "  make update      Update tools and templates"
	@echo "  make test        Run syntax checks"
	@echo ""
	@echo "Examples:"
	@echo "  make scan TARGET=example.com"
	@echo "  make scan TARGET=example.com ARGS='--fast'"
	@echo ""

# Docker build
build:
	docker build -t hybridrecon-x .

# Run interactive shell
run:
	docker run -it --rm --network=host \
		-v $(PWD)/output:/hybridrecon/output \
		hybridrecon-x /bin/bash

# Run scan with TARGET
scan:
ifndef TARGET
	$(error TARGET is not set. Usage: make scan TARGET=domain.com)
endif
	docker run -it --rm --network=host \
		-v $(PWD)/output:/hybridrecon/output \
		hybridrecon-x ./hybrid_x.sh -d $(TARGET) $(ARGS)

# Fast scan
fast:
ifndef TARGET
	$(error TARGET is not set. Usage: make fast TARGET=domain.com)
endif
	docker run -it --rm --network=host \
		-v $(PWD)/output:/hybridrecon/output \
		hybridrecon-x ./hybrid_x.sh -d $(TARGET) --fast

# Local installation
install:
	sudo ./install.sh

# Check tools
check:
	@echo "Checking tool availability..."
	@./hybrid_x.sh --check-tools 2>/dev/null || python3 lib/tool_registry.py --status

# Clean output
clean:
	@echo "Cleaning output directories..."
	rm -rf output/*
	rm -rf .hybridrecon_state/*
	rm -f *.log
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Done."

# Update tools
update:
	@echo "Updating Nuclei templates..."
	nuclei -update-templates -silent || true
	@echo "Updating Go tools..."
	go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
	@echo "Done."

# Syntax test
test:
	@echo "Running syntax checks..."
	@for f in modules/*.sh hybrid_x.sh lib/*.sh; do \
		bash -n "$$f" && echo "$$f: OK" || echo "$$f: FAIL"; \
	done
	@for f in modules/*.py lib/*.py; do \
		python3 -m py_compile "$$f" && echo "$$f: OK" || echo "$$f: FAIL"; \
	done
	@echo "All checks complete."

# Validate config
validate-config:
	@python3 -c "import yaml; yaml.safe_load(open('config.yaml'))" && echo "config.yaml: Valid"

# Docker shell
shell: run

# Version info
version:
	@grep "VERSION=" hybrid_x.sh | head -1
	@grep "version:" config.yaml | head -1
