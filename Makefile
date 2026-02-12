# Makefile for VirusTotal API SDK

.PHONY: help test test-unit test-acceptance test-all lint fmt vet clean

# Default target
help:
	@echo "Available targets:"
	@echo "  test              - Run unit tests (mocked)"
	@echo "  test-unit         - Run unit tests (mocked)"
	@echo "  test-acceptance   - Run acceptance tests (real API calls)"
	@echo "  test-all          - Run all tests (unit + acceptance)"
	@echo "  lint              - Run golangci-lint"
	@echo "  fmt               - Format code with gofmt"
	@echo "  vet               - Run go vet"
	@echo "  clean             - Clean build artifacts"
	@echo ""
	@echo "Environment variables for acceptance tests:"
	@echo "  VT_API_KEY        - VirusTotal API key (required)"
	@echo "  VT_VERBOSE        - Enable verbose test output (default: false)"
	@echo "  VT_SKIP_CLEANUP   - Skip cleanup after tests (default: false)"

# Run unit tests (excludes acceptance tests)
test: test-unit

test-unit:
	@echo "Running unit tests..."
	@go test -v -race -coverprofile=coverage.txt -covermode=atomic ./virustotal/...

# Run acceptance tests (requires VT_API_KEY)
test-acceptance:
	@if [ -z "$(VT_API_KEY)" ]; then \
		echo "Error: VT_API_KEY environment variable is not set"; \
		echo "Please set your VirusTotal API key:"; \
		echo "  export VT_API_KEY=your-api-key"; \
		exit 1; \
	fi
	@echo "Running acceptance tests (this may take a while due to rate limiting)..."
	@VT_API_KEY=$(VT_API_KEY) go test -v -timeout 30m ./virustotal/acceptance/...

# Run all tests
test-all: test-unit test-acceptance

# Run golangci-lint
lint:
	@echo "Running golangci-lint..."
	@golangci-lint run --config=./.golangci.yml --timeout=30m

# Format code
fmt:
	@echo "Formatting code..."
	@gofmt -s -w .

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f coverage.txt
	@go clean -cache -testcache
