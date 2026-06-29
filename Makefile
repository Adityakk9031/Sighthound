# Sighthound Vulnerability Scanner Makefile

.PHONY: all build test test-unit test-all clean install help

# Default target
all: build test

# Build the project
build:
	@echo "🔨 Building Sighthound..."
	cargo build --release

# Run the Rust test suite via cargo test (under repair)
test-unit:
	@echo "🦀 Running Rust tests..."
	cargo test

# Run all tests (cargo test runs unit + integration + end_to_end harnesses)
test-all: test-unit

# Canonical test entry point
test: test-all

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
	rm -rf target/

# Install binary to system
install: build
	@echo "📦 Installing Sighthound..."
	cargo install --path .

# Show help
help:
	@echo "Sighthound Vulnerability Scanner Build System"
	@echo "============================================="
	@echo ""
	@echo "Available targets:"
	@echo "  build       - Build the release binary"
	@echo "  test        - Run cargo test (under repair; some modules disabled)"
	@echo "  test-unit   - Run cargo test"
	@echo "  test-all    - Run cargo test"
	@echo "  clean       - Clean build artifacts"
	@echo "  install     - Install binary to system"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Quick commands:"
	@echo "  make build  - Build the release binary"
	@echo "  make test   - Run cargo test (under repair)"
