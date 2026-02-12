# Makefile for VirusTotal API SDK

.PHONY: help test test-unit test-acceptance test-all lint fmt vet clean

help:
	@echo "Available targets:"
	@echo "  test              - Run unit tests"
	@echo "  test-acceptance   - Run acceptance tests (CI only)"
	@echo "  lint              - Run golangci-lint"
	@echo "  fmt               - Format code"
	@echo "  vet               - Run go vet"
	@echo "  clean             - Clean build artifacts"

# Run unit tests (excludes acceptance tests)
test: test-unit

test-unit:
	@echo "Running unit tests..."
	@go test -v -race -coverprofile=coverage.txt -covermode=atomic ./virustotal/...

# Run acceptance tests (CI/CD only - requires VT_API_KEY secret)
test-acceptance:
	@go test -v -timeout 30m ./virustotal/acceptance/...

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
